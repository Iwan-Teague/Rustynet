#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);
const PING_EXIT_MARKER: &str = "__RUSTYNET_PING_EXIT=";

/// Flush every `rustynet*` nftables table (the bootstrap killswitch
/// `rustynet_boot` AND any runtime generation table such as `rustynet_g1` a
/// crashed daemon left behind). Their default OUTPUT policy is drop, which would
/// block the next bootstrap's outbound traffic (incl. cargo registry downloads).
/// Enumerated (not a fixed name) so an unanticipated table cannot leave egress
/// blocked; idempotent (no matching tables → no-op) and best-effort.
///
/// The table list is captured into `$rn_tables` FIRST, then iterated with a
/// `for` loop. The obvious `nft list tables | awk … | while read t; do sudo
/// nft delete …; done` is BROKEN: the `sudo` inside the loop shares the loop's
/// stdin (the awk pipe) and drains it, so `read` never sees the table names and
/// nothing is deleted. That silent no-op left `rustynet_boot` behind on every
/// run; `assert_node_clean` (C2) is what surfaced it. Capture-then-`for` has no
/// pipe for the inner `sudo` to consume.
///
/// Wrapped in a bounded retry-until-clean loop: the `rustynet_boot` L8 boot
/// killswitch is installed at the daemon's `ExecStartPre` and survives teardown
/// by design, and a daemon torn down mid-shutdown (or a restart that fires
/// inside `RestartSec` right as cleanup disables it) can re-program a table
/// after a single delete pass. Re-deleting until no `rustynet*` table remains
/// converges once the daemon is actually down (nothing re-applies the table with
/// the unit stopped).
///
/// PATH: `nft` lives in `/usr/sbin`, which a non-login SSH shell's PATH omits on
/// Debian (`/usr/local/bin:/usr/bin:/bin:/usr/games`). The `command -v nft` gate
/// therefore FAILED and the whole reset was silently skipped, leaving
/// `rustynet_boot` behind on every run (found 2026-07-13 chasing the Pair-1 P1-2
/// residue: the reset never ran, and the `assert_node_clean` probe fail-open hid
/// it). The `sudo -n nft delete` calls worked (root's PATH has `/usr/sbin`) — only
/// the user-context gate missed — so prepend the sbin dirs to PATH.
const LINUX_NFT_KILLSWITCH_RESET_COMMAND: &str = "export PATH=\"/usr/sbin:/sbin:$PATH\"; \
     if command -v nft >/dev/null 2>&1; then \
         for _ in $(seq 1 10); do \
             rn_tables=$(sudo -n nft list tables 2>/dev/null \
                 | awk '$2==\"inet\" && $3 ~ /^rustynet/ {print $3}'); \
             [ -z \"$rn_tables\" ] && break; \
             for t in $rn_tables; do sudo -n nft delete table inet \"$t\" 2>/dev/null || true; done; \
             sleep 0.5; \
         done; \
     fi";

/// Tear down any residual `rustynet*` WireGuard/TUN interface a crashed daemon
/// left behind (the dataplane device is `rustynet0`, but a generation-suffixed
/// device such as `rustynet1` from an aborted rebuild is also possible). A stale
/// interface still carrying the mesh CIDR collides with the next bootstrap's
/// fresh device bring-up, so it must go once the daemon is confirmed down.
///
/// Enumerated (not a fixed `rustynet0`) for the same reason the nft reset is:
/// an unanticipated generation device cannot be left behind. Idempotent — no
/// matching link is a no-op — and best-effort at every privileged step
/// (`|| true`), so a node that never had an interface does not fail the reset.
/// Runs AFTER the daemon-stop wait so nothing re-creates the device mid-delete.
const LINUX_INTERFACE_RESET_COMMAND: &str = "export PATH=\"/usr/sbin:/sbin:$PATH\"; \
     if command -v ip >/dev/null 2>&1; then \
         rn_links=$(ip -o link show 2>/dev/null \
             | awk -F': ' '{print $2}' | awk -F'@' '{print $1}' \
             | awk '/^rustynet/ {print}'); \
         for link in $rn_links; do \
             sudo -n ip link delete \"$link\" 2>/dev/null || true; \
         done; \
     fi";

/// Comprehensive post-cleanup verification probe used by [`assert_node_clean`].
/// Emits exactly three space-separated tokens on a single line that
/// [`parse_node_clean_probe`] interprets:
///   `nft=<names|->`   leftover `rustynet*` inet table names, or `-` if none
///   `daemon=<up|down>` whether `rustynetd` or `rustynet-relay` is still running
///   `iface=<names|->`  leftover `rustynet*` interface names, or `-` if none
///
/// A node is clean only when all three are benign (`nft=-`, `daemon=down`,
/// `iface=-`). A tool genuinely absent yields the benign token (a host without
/// `nft` cannot carry a leftover nft table); but a tool that IS present whose
/// query fails (e.g. `sudo -n` denied) yields `unknown` → treated as DIRTY by
/// [`parse_node_clean_probe`], NOT benign — the residue control fails CLOSED, so
/// an unverifiable node is never passed as clean. Read-only.
///
/// PATH: prepend `/usr/sbin:/sbin` so `command -v nft` finds `/usr/sbin/nft`. A
/// non-login SSH shell's PATH omits `/usr/sbin` on Debian, so the old
/// `command -v nft` gate short-circuited and reported `nft=-` (clean) with the
/// `rustynet_boot` killswitch still installed — a fail-OPEN that hid the Pair-1
/// P1-2 residue (found + fixed 2026-07-13).
const LINUX_NODE_CLEAN_PROBE: &str = "export PATH=\"/usr/sbin:/sbin:$PATH\"; \
     if command -v nft >/dev/null 2>&1; then \
         if rn_tbls=$(sudo -n nft list tables 2>/dev/null); then \
             rn_nft=$(printf '%s\\n' \"$rn_tbls\" \
                 | awk '$2==\"inet\" && $3 ~ /^rustynet/ {print $3}' | tr '\\n' ','); \
         else \
             rn_nft=unknown; \
         fi; \
     else \
         rn_nft=; \
     fi; \
     rn_daemon=$(if pgrep -x rustynetd >/dev/null 2>&1 \
         || pgrep -x rustynet-relay >/dev/null 2>&1; then echo up; else echo down; fi); \
     if command -v ip >/dev/null 2>&1; then \
         if rn_links=$(ip -o link show 2>/dev/null); then \
             rn_iface=$(printf '%s\\n' \"$rn_links\" \
                 | awk -F': ' '{print $2}' | awk -F'@' '{print $1}' \
                 | awk '/^rustynet/ {print}' | tr '\\n' ','); \
         else \
             rn_iface=unknown; \
         fi; \
     else \
         rn_iface=; \
     fi; \
     printf 'nft=%s daemon=%s iface=%s\\n' \
         \"${rn_nft:--}\" \"$rn_daemon\" \"${rn_iface:--}\"";

/// Pure parser for [`LINUX_NODE_CLEAN_PROBE`] output. Returns `Ok(())` when the
/// node is verifiably clean (no leftover `rustynet*` nft table, no running
/// `rustynetd`, no leftover `rustynet*` interface) and a descriptive
/// `node still dirty: …` error listing every dirty dimension otherwise.
///
/// Fail closed: any token that is missing, malformed, or does not explicitly
/// assert the benign value is treated as dirty. A truncated or garbled probe
/// (e.g. SSH noise prepended) therefore fails the assertion rather than passing
/// a node whose true state is unknown — exactly the posture `assert_node_clean`
/// is meant to enforce.
fn parse_node_clean_probe(raw: &str) -> Result<(), AdapterError> {
    // The probe prints a single result line; tolerate leading log/banner lines
    // by scanning for the line that carries the three expected tokens.
    let line = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .rev()
        .find(|l| l.contains("nft=") && l.contains("daemon=") && l.contains("iface="));
    let Some(line) = line else {
        return Err(AdapterError::Protocol {
            message: format!(
                "node still dirty: clean-probe output unrecognised (fail closed): {:?}",
                raw.trim()
            ),
        });
    };

    let mut nft: Option<&str> = None;
    let mut daemon: Option<&str> = None;
    let mut iface: Option<&str> = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("nft=") {
            nft = Some(v);
        } else if let Some(v) = tok.strip_prefix("daemon=") {
            daemon = Some(v);
        } else if let Some(v) = tok.strip_prefix("iface=") {
            iface = Some(v);
        }
    }

    // `-` (or empty) is the benign "nothing leftover" sentinel; any other value
    // is a comma-joined list of leftover resource names. Strip a trailing comma
    // the `tr '\n' ','` join leaves on a non-empty list.
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
    match clean_list(nft) {
        Some(s) if s.is_empty() => {}
        Some(s) => dirty.push(format!("nftables table(s): {s}")),
        None => dirty.push("nftables status unknown (probe token missing)".to_owned()),
    }
    match daemon {
        Some("down") => {}
        Some("up") => dirty.push("rustynetd or rustynet-relay still running".to_owned()),
        _ => dirty.push("daemon status unknown (probe token missing)".to_owned()),
    }
    match clean_list(iface) {
        Some(s) if s.is_empty() => {}
        Some(s) => dirty.push(format!("interface(s): {s}")),
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

/// Collect `WireGuard` public key from `/var/lib/rustynet/keys/wireguard.pub`.
/// Returns the base64-encoded key as a hex string (32-byte decode → hex).
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let raw = ssh::run_remote(
        conn,
        "if sudo -n true >/dev/null 2>&1; then \
             sudo -n cat /var/lib/rustynet/keys/wireguard.pub; \
         else \
             cat /var/lib/rustynet/keys/wireguard.pub; \
         fi",
        SHORT_TIMEOUT,
    )?;
    let hex = decode_wireguard_pubkey_to_hex(raw.trim())
        .map_err(|err| AdapterError::Protocol { message: err })?;
    Ok(hex)
}

/// Read the local `node_id` from the running daemon via `rustynet status`.
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    // /run/rustynet/ is mode 770 root:rustynetd; the daemon control socket
    // is unreadable to a non-root SSH user, so the status query needs sudo.
    //
    // This runs in the CollectPubkeys stage, immediately after bootstrap.
    // `install_daemon` does NOT wait for the socket (unlike the macOS path),
    // and systemd reports the unit active before the daemon binds its socket,
    // so a single status query can race the daemon's startup. Retry for up to
    // ~40 s (matching the macOS socket wait) before giving up.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        let attempt_err = match ssh::run_remote(
            conn,
            "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock /usr/local/bin/rustynet status",
            SHORT_TIMEOUT,
        ) {
            Ok(status) => match ssh::parse_status_node_id(&status) {
                Some(node_id) => return Ok(node_id),
                None => AdapterError::Protocol {
                    message: format!(
                        "node_id field not found in rustynet status output: {}",
                        &status[..status.len().min(200)]
                    ),
                },
            },
            Err(e) => e,
        };
        if std::time::Instant::now() >= deadline {
            return Err(attempt_err);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Positive connectivity: ping `peer_mesh_ip` 3 times via the tunnel.
/// Returns `TrafficTestResult::Reachable` on success.
/// On failure, captures the full ping stdout/stderr so the stage log
/// carries diagnostic detail (timeout vs unreachable vs packet loss)
/// instead of a bare "ping to X failed".
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    // Always return a successful remote shell so the stage retains ping stdout
    // on failure. `ssh::run_remote` otherwise returns only its transport error
    // path, which erased the route/timeout evidence needed to diagnose the
    // full-mesh client↔client failure. The IP is strictly validated above.
    let script = format!(
        "set +e; ping -c 3 -W 5 {peer_mesh_ip} 2>&1; rn_ping_status=$?; \
         printf '\\n{PING_EXIT_MARKER}%s\\n' \"$rn_ping_status\"; exit 0"
    );
    let output = ssh::run_remote(conn, &script, Duration::from_secs(30))?;
    parse_ping_result(peer_mesh_ip, output.as_str())
}

fn parse_ping_result(peer_mesh_ip: &str, output: &str) -> Result<TrafficTestResult, AdapterError> {
    let Some((diagnostic, status)) = output.rsplit_once(PING_EXIT_MARKER) else {
        return Err(AdapterError::Protocol {
            message: format!(
                "ping diagnostic protocol missing exit marker for {peer_mesh_ip} (fail closed)"
            ),
        });
    };
    let status = status.trim();
    let exit_code = status.parse::<i32>().map_err(|_| AdapterError::Protocol {
        message: format!(
            "ping diagnostic protocol has invalid exit status {:?} for {peer_mesh_ip} (fail closed)",
            status
        ),
    })?;
    if exit_code == 0 {
        Ok(TrafficTestResult::Reachable)
    } else {
        Ok(TrafficTestResult::Error(format!(
            "ping to {peer_mesh_ip} failed (exit {exit_code}): {}",
            diagnostic.trim()
        )))
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked by default-deny policy.
/// MUST return `TrafficTestResult::Blocked` for the stage to pass.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    // ping with a very short deadline — we expect it to fail immediately.
    let script = format!("ping -c 1 -W 2 {denied_ip} >/dev/null 2>&1");
    match ssh::run_remote_check(conn, &script, Duration::from_secs(10))? {
        // Ping succeeded → traffic reached the denied target → security failure.
        true => Ok(TrafficTestResult::Reachable),
        // Ping failed → as expected, traffic is blocked.
        false => Ok(TrafficTestResult::Blocked),
    }
}

/// Collect list of active `WireGuard` tunnels from `wg show all latest-handshakes`.
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let output = ssh::run_remote(
        conn,
        "if command -v wg >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then \
                 sudo -n wg show all latest-handshakes 2>&1; \
             else \
                 wg show all latest-handshakes 2>&1; \
             fi; \
         else \
             echo wg-not-installed; \
         fi",
        SHORT_TIMEOUT,
    )?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(std::string::ToString::to_string)
        .collect();

    // Kernel WireGuard backends expose peers via `wg show`. The
    // `linux-wireguard-userspace-shared` backend (boringtun on a TUN device)
    // registers nothing with kernel `wg`, so `wg show` is empty (or `wg` is
    // absent) even with a live tunnel carrying traffic. Fall back to the
    // daemon's own status, which is backend-agnostic: a non-fail-closed daemon
    // with at least one programmed peer tunnel is an active tunnel.
    let kernel_wg_unusable =
        tunnels.is_empty() || tunnels.iter().all(|l| l.contains("wg-not-installed"));
    if kernel_wg_unusable {
        let status = ssh::run_remote(
            conn,
            "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock /usr/local/bin/rustynet status 2>/dev/null || true",
            SHORT_TIMEOUT,
        )?;
        let derived = tunnels_from_daemon_status(&status);
        if !derived.is_empty() {
            return Ok(TunnelsList { tunnels: derived });
        }
    }
    Ok(TunnelsList { tunnels })
}

/// Derive the active-tunnel list from `rustynet status` (space-separated
/// `key=value` tokens) for backends `wg show` cannot see. Returns one synthetic
/// line per programmed peer when the daemon is NOT fail-closed
/// (`restriction_mode=None`) and has at least one programmed peer tunnel
/// (`path_programmed_peer_count>=1`); otherwise empty (fail-closed: a restricted
/// daemon or a zero-peer dataplane is not an active tunnel).
fn tunnels_from_daemon_status(status: &str) -> Vec<String> {
    let value = |key: &str| {
        status
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
    };
    let not_restricted = value("restriction_mode=") == Some("None");
    let programmed = value("path_programmed_peer_count=")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if !not_restricted || programmed == 0 {
        return Vec::new();
    }
    let mode = value("path_programmed_mode=").unwrap_or("programmed");
    (0..programmed)
        .map(|i| {
            format!("userspace-shared peer {i}: {mode} (dataplane applied, restriction_mode=None)")
        })
        .collect()
}

/// Drive sustained external (non-mesh) traffic from a Linux client so that —
/// when the client is full-tunnel through the exit — it egresses via the exit's
/// NAT, surfacing as a NAT session on the exit. Starts a backgrounded burst of
/// TCP connects to a stable external anycast IP (`1.1.1.1:443`, Cloudflare; a
/// bare connect, no payload) and returns immediately so the connection window
/// overlaps the exit's NAT-session check.
pub fn drive_exit_egress_probe(conn: &NodeConnection) -> Result<(), AdapterError> {
    let cmd = "nohup sh -c 'for i in $(seq 1 30); do \
         timeout 2 bash -c \"exec 3<>/dev/tcp/1.1.1.1/443\" 2>/dev/null; \
         sleep 0.4; done' >/dev/null 2>&1 & echo probe_started";
    let out = ssh::run_remote(conn, cmd, SHORT_TIMEOUT)?;
    if out.contains("probe_started") {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!("failed to start client exit-egress probe: {}", out.trim()),
        })
    }
}

/// The Linux daemon's local control socket (a UNIX-domain socket, mode 770
/// root:rustynetd). Mirrors `rustynetd::daemon::DEFAULT_SOCKET_PATH` for the
/// Linux build; the orchestrator's SSH user is non-root, so every command that
/// talks to it is wrapped in `sudo -n`. Kept as a single constant so the
/// route-advertise activation and any future socket-bound probe stay in sync
/// with the daemon.
const LINUX_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

/// Activate full-tunnel exit-serving on the Linux exit: advertise the default
/// route (`0.0.0.0/0`) to the live daemon over its control socket. This is the
/// operator "become an exit node" action — the daemon responds by applying IPv4
/// forwarding + an nftables MASQUERADE NAT table (`apply_nat_forwarding` in
/// rustynetd `phase10`) for mesh client traffic. The lab's standard flow never
/// sends it, so an exit otherwise only validates its role/posture/mesh, never
/// active NAT egress.
///
/// The invocation is the same one the live bash orchestrator drives:
/// `sudo -n env RUSTYNET_DAEMON_SOCKET=<sock> /usr/local/bin/rustynet route advertise
/// 0.0.0.0/0` — every token is a compile-time constant (no untrusted
/// interpolation), so it is argv-only-safe. On the daemon rejecting the
/// advertisement (e.g. a node not permitted to serve / restricted / safe-mode),
/// `rustynet` exits non-zero and prints the daemon's own reason
/// (`route advertise denied: <reason>`); that surfaces here as the returned
/// error so a host that cannot serve fails closed with a clear message. The
/// stage additionally appends `collect_daemon_failure_reason` for defence in
/// depth.
pub fn activate_exit_serving(conn: &NodeConnection) -> Result<(), AdapterError> {
    let script = format!(
        "sudo -n env RUSTYNET_DAEMON_SOCKET={LINUX_DAEMON_SOCKET} \
         /usr/local/bin/rustynet route advertise 0.0.0.0/0"
    );
    match ssh::run_remote(conn, &script, SHORT_TIMEOUT) {
        Ok(_) => Ok(()),
        // A non-zero exit carries the daemon's own rejection reason. `rustynet`
        // prints its error to stdout (`error [..]: route advertise denied: ..`);
        // run_remote folds that stdout tail into the Command stderr when the
        // process stderr is empty, so the captured text holds the cause.
        Err(AdapterError::Command { stderr, .. }) => Err(AdapterError::Protocol {
            message: format!(
                "daemon rejected exit-serving route advertisement: {}",
                stderr.trim()
            ),
        }),
        Err(other) => Err(other),
    }
}

/// Assert the Linux exit is ACTIVELY serving as a full-tunnel exit — proving the
/// dataplane actually came up, not merely that the exit role is held. Asserts
/// BOTH:
///   (a) IPv4 forwarding is enabled (`/proc/sys/net/ipv4/ip_forward` == `1`), and
///   (b) an nftables MASQUERADE rule exists in the rustynet NAT table
///       (`table ip rustynet_nat_g<N>`, chain `postrouting`, a `… masquerade`
///       rule on the egress interface), built by `apply_nat_forwarding` in
///       rustynetd `phase10` (the `rustynet_nat_g{generation}` ip table with a
///       `oifname <egress> masquerade` rule under the postrouting nat chain).
///
/// Fails closed: an empty/missing ruleset, forwarding disabled, or no masquerade
/// rule => `Err`. A non-NATing exit must NOT pass.
pub fn assert_exit_actively_serving(conn: &NodeConnection) -> Result<(), AdapterError> {
    // (a) IPv4 forwarding. Read the sysctl directly; trim because the file is
    // newline-terminated. `cat` of a world-readable proc file needs no sudo.
    let fwd = ssh::run_remote(
        conn,
        "cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo MISSING",
        SHORT_TIMEOUT,
    )?;
    if fwd.trim() != "1" {
        return Err(AdapterError::Protocol {
            message: format!(
                "Linux exit is not actively serving: IPv4 forwarding not enabled \
                 (/proc/sys/net/ipv4/ip_forward = {})",
                fwd.trim()
            ),
        });
    }

    // (b) nftables MASQUERADE rule in the rustynet NAT table. /run + nft state
    // are root-only, so the ruleset dump needs sudo.
    let ruleset = ssh::run_remote(
        conn,
        "sudo -n nft list ruleset 2>/dev/null || true",
        SHORT_TIMEOUT,
    )?;
    if !ruleset_has_rustynet_masquerade(&ruleset) {
        return Err(AdapterError::Protocol {
            message:
                "Linux exit is not actively serving: no rustynet NAT masquerade rule found in \
                 nft ruleset (expected `table ip rustynet_nat_g<N>` with a masquerade rule)"
                    .to_owned(),
        });
    }
    Ok(())
}

/// On the Linux exit, assert a conntrack entry shows a mesh-sourced
/// (`100.64.0.0/10`) client flow being NAT-translated outbound — direct proof
/// that a client's full-tunnel traffic egresses via THIS exit's NAT (the W1/D7
/// "client mesh traffic egresses via the exit" evidence). Retries internally to
/// cover the client's full-tunnel convergence + the egress-probe window.
///
/// Reads conntrack via `conntrack -L`, falling back to `/proc/net/nf_conntrack`
/// when the `conntrack` tool is absent, and matches a line whose ORIGINAL `src`
/// is in `100.64.0.0/10` AND whose reply tuple is translated (the reply `dst`
/// differs from the original `src`, i.e. SNAT/masquerade rewrote the source).
///
/// Fails closed: no matching translated mesh flow => `Err`.
pub fn assert_mesh_client_nat_session(conn: &NodeConnection) -> Result<(), AdapterError> {
    // conntrack -L is the canonical view; if the userspace tool is missing fall
    // back to the kernel's /proc/net/nf_conntrack. Both are root-readable only.
    let probe = "if command -v conntrack >/dev/null 2>&1; then \
             sudo -n conntrack -L 2>/dev/null; \
         else \
             sudo -n cat /proc/net/nf_conntrack 2>/dev/null; \
         fi || true";
    for attempt in 0..10 {
        let out = ssh::run_remote(conn, probe, MEDIUM_TIMEOUT)?;
        if out.lines().any(conntrack_line_is_translated_mesh) {
            return Ok(());
        }
        if attempt < 9 {
            std::thread::sleep(Duration::from_millis(1500));
        }
    }
    Err(AdapterError::Protocol {
        message:
            "Linux exit shows no conntrack session translating a mesh-sourced (100.64.0.0/10) \
             client address outbound (no client-egress NAT session converged)"
                .to_owned(),
    })
}

/// Collect diagnostic artifacts from the remote host to `dst`.
/// Key material paths (`*/keys/*`, `*.priv`, `*.pem`) MUST NOT appear in
/// the archive. This is enforced by the `--exclude` arguments to tar and
/// verified by the key-exclusion invariant test.
pub fn collect_artifacts(conn: &NodeConnection, dst: &std::path::Path) -> Result<(), AdapterError> {
    use std::time::Duration;

    let remote_tmp = "/tmp/rn_diag_artifacts.tar.gz";
    // Create archive on remote, excluding key material. /var/lib/rustynet/
    // and /run/rustynet/ are root-owned, mode 700/770; tar needs sudo to
    // read into them. We then chown the archive back so scp_from (running
    // as the SSH user) can read it.
    let tar_script = format!(
        "sudo -n tar -czf {remote_tmp} \
         --exclude='*/keys/*' \
         --exclude='*.priv' \
         --exclude='*.pem' \
         --exclude='*.key' \
         --ignore-failed-read \
         /var/lib/rustynet/ \
         /var/log/ \
         /run/rustynet/ \
         2>/dev/null; \
         sudo -n chown \"$(id -u):$(id -g)\" {remote_tmp} 2>/dev/null; \
         true"
    );
    ssh::run_remote(conn, &tar_script, Duration::from_secs(60))?;

    // Download the archive.
    ssh::scp_from(conn, remote_tmp, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let _ = ssh::run_remote(conn, &format!("rm -f {remote_tmp}"), SHORT_TIMEOUT);

    // Verify the archive contains no key material — security invariant check.
    verify_no_key_material(dst)?;

    Ok(())
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Disable + stop the ENTIRE rustynet systemd footprint and WAIT until no
    // rustynetd process remains BEFORE the nft reset below. A daemon — or a
    // timer-driven service — re-applies the `rustynet_boot` fail-closed
    // killswitch after the reset deletes it, which then trips assert_node_clean.
    // Three refinements over stopping `rustynetd` alone:
    //   1. The unit set is ENUMERATED dynamically (`systemctl list-unit-files`
    //      filtered to `rustynet*`), not a fixed list. A node re-provisioned
    //      into a new role can be running units from a prior role —
    //      `rustynet-relay`, `rustynetd-privileged-helper`,
    //      `rustynetd-managed-dns`, the refresh timers, and crucially the
    //      `rustynet-push-all.timer` bundle-distribution timer, which fires
    //      periodically and re-applies `rustynet_boot` minutes after cleanup.
    //      Observed live as assert_node_clean finding `rustynet_boot` on the
    //      exit node even after a clean reset, because the enabled push-all
    //      timer re-installed it between the reset and the assertion. Enumerating
    //      catches every unit, including any added later.
    //   2. The wait keys on the actual PROCESS (`pgrep -x rustynetd`), not the
    //      systemd unit state, so a daemon launched outside `rustynetd.service`
    //      (or still mid-shutdown re-applying the boot table) is waited out.
    //   3. A `sudo pkill -x rustynetd` backstop terminates any stray daemon the
    //      units do not own (after `disable --now`, so systemd will not restart
    //      it). reset-failed clears failed-unit latches.
    // Best-effort: a host without any rustynet unit is a no-op.
    let _ = ssh::run_remote(
        conn,
        "rn_units=$(systemctl list-unit-files 2>/dev/null \
             | awk '$1 ~ /^rustynet/ {print $1}'); \
         for unit in $rn_units; do \
             sudo -n systemctl disable --now \"$unit\" 2>/dev/null || true; \
         done; \
         sudo -n pkill -x rustynetd 2>/dev/null || true; \
         for _ in $(seq 1 60); do \
             pgrep -x rustynetd >/dev/null 2>&1 && sleep 0.5 || break; \
         done; \
         for unit in $rn_units; do \
             sudo -n systemctl reset-failed \"$unit\" 2>/dev/null || true; \
         done",
        Duration::from_secs(60),
    );
    // Flush every rustynet nftables table the daemon may have left behind so the
    // next bootstrap is not blocked by a leftover default-deny killswitch.
    let _ = ssh::run_remote(
        conn,
        LINUX_NFT_KILLSWITCH_RESET_COMMAND,
        Duration::from_secs(30),
    );
    // Tear down any residual `rustynet*` WireGuard/TUN interface a crashed daemon
    // left up. Runs AFTER the daemon-stop wait above so nothing re-creates the
    // device mid-delete; a stale interface still carrying the mesh CIDR would
    // collide with the next bootstrap's fresh device bring-up. Best-effort and
    // idempotent — no matching link is a no-op.
    let _ = ssh::run_remote(conn, LINUX_INTERFACE_RESET_COMMAND, Duration::from_secs(30));
    // Restart systemd-resolved so the next bootstrap inherits a clean DNS
    // stub. The daemon's network plumbing can leave the stub at 127.0.0.53
    // in a degraded state after teardown, causing DNS timeouts during cargo
    // registry downloads in the subsequent bootstrap stage.
    let _ = ssh::run_remote(
        conn,
        "if command -v systemctl >/dev/null 2>&1 && \
              systemctl is-active systemd-resolved >/dev/null 2>&1; then \
             sudo -n systemctl restart systemd-resolved 2>/dev/null || true; \
         fi",
        Duration::from_secs(30),
    );
    // Privileged: state files are root:rustynetd, mode 600/640.
    ssh::run_remote(
        conn,
        // rustynetd.state persists operational state (incl. selected_exit_node)
        // across restarts; purge it on rebuild so the daemon re-derives its exit
        // selection from the freshly distributed auto-tunnel bundle rather than
        // a stale prior-topology value (see macos_traffic::cleanup_runtime_state
        // for the live failure mode). No anti-replay watermark lives in it.
        "sudo -n rm -rf /run/rustynet \
         /var/lib/rustynet/membership.snapshot \
         /var/lib/rustynet/membership.log \
         /var/lib/rustynet/membership.watermark \
         /var/lib/rustynet/rustynetd.assignment \
         /var/lib/rustynet/rustynetd.assignment.watermark \
         /var/lib/rustynet/rustynetd.traversal \
         /var/lib/rustynet/rustynetd.traversal.watermark \
         /var/lib/rustynet/rustynetd.dns-zone \
         /var/lib/rustynet/rustynetd.state \
         /var/lib/rustynet/rustynetd.trust 2>/dev/null; true",
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Best-effort: the Linux daemon's own fail-closed/startup reason, read from
/// `/var/lib/rustynet/logs/rustynetd.log`, so an enforce failure reports the
/// cause rather than just the daemon-socket-timeout symptom.
pub fn collect_daemon_failure_reason(
    conn: &NodeConnection,
) -> Result<Option<String>, AdapterError> {
    let tail = ssh::run_remote(
        conn,
        "sudo -n tail -n 200 /var/lib/rustynet/logs/rustynetd.log 2>/dev/null || true",
        SHORT_TIMEOUT,
    )?;
    Ok(crate::vm_lab::orchestrator::adapter::node_adapter::extract_daemon_failure_reason(&tail))
}

/// After cleanup, assert the node is verifiably clean across all three
/// dimensions that break the next bootstrap: no leftover `rustynet*` nftables
/// killswitch table (a default-deny table starves egress), no running
/// `rustynetd` (a live daemon re-applies the killswitch and owns the
/// interface), and no leftover `rustynet*` WireGuard/TUN interface (a stale
/// device collides with the fresh bring-up). Fails loudly so a reset that did
/// not take is caught here, not as a cargo DNS timeout five stages later.
///
/// Checking the daemon and interface — not just the nft table — closes the gap
/// where a daemon mid-shutdown (or relaunched inside `RestartSec`) had already
/// re-deleted/re-added the table between the reset and an nft-only probe, so the
/// node read "clean" while still actively dirty.
pub fn assert_node_clean(conn: &NodeConnection) -> Result<(), AdapterError> {
    let raw = ssh::run_remote(conn, LINUX_NODE_CLEAN_PROBE, SHORT_TIMEOUT)?;
    parse_node_clean_probe(&raw)
}

/// Verify SSH connectivity by running a no-op command.
pub fn check_ssh_reachable(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(conn, "echo reachable", Duration::from_secs(10))?;
    Ok(())
}

/// Collect the `WireGuard` mesh IP from the running daemon interface or status.
pub fn collect_mesh_ip(conn: &NodeConnection) -> Result<String, AdapterError> {
    let ip = ssh::run_remote(
        conn,
        "ip addr show rustynet0 2>/dev/null \
         | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1 || echo ''",
        SHORT_TIMEOUT,
    )?;
    let ip = ip.trim().to_owned();
    if !ip.is_empty() {
        return Ok(ip);
    }
    let status = ssh::run_remote(
        conn,
        "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock /usr/local/bin/rustynet status 2>/dev/null || echo ''",
        SHORT_TIMEOUT,
    )?;
    ssh::parse_status_field(&status, "mesh_ip")
        .or_else(|| ssh::parse_status_field(&status, "wg_ip"))
        .ok_or_else(|| AdapterError::Protocol {
            message: "mesh IP not found via rustynet0 interface or rustynet status".to_owned(),
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

    // Ensure /etc/rustynet/ has the strict mode 0750 root:rustynetd that
    // validate_key_custody_permissions requires before the signing-secret load.
    // install-systemd sets this during bootstrap, but some bootstrap paths
    // leave it at 0755 if install-systemd runs before the rustynetd group GID
    // is fully resolved.  Re-enforcing here is safe and idempotent.
    ssh::run_remote(
        conn,
        "sudo -n chmod 0750 /etc/rustynet && \
         sudo -n chown root:rustynetd /etc/rustynet",
        SHORT_TIMEOUT,
    )?;

    let safe_rustynet = rustynet_path.replace('\'', "'\"'\"'");
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n env RUSTYNET_NODE_ROLE=admin \
             '{safe_rustynet}' ops {issue_subcmd} \
             --env-file '{remote_env}' --issue-dir '{remote_issue_dir}'"
        ),
        MEDIUM_TIMEOUT,
    )?;

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

/// Validate that an IP address argument contains no shell-dangerous characters.
fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    if ip
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/'))
    {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "IP argument '{ip}' contains characters not safe for shell embedding \
                 (allowed: alphanumeric, '.', ':', '/')"
            ),
        })
    }
}

/// True when `addr` (a bare IPv4 dotted-quad) is in the mesh CGNAT range
/// `100.64.0.0/10` — first octet 100, second octet 64–127. Mirrors the Windows
/// adapter's mesh-source classification so the cross-OS NAT-session evidence is
/// defined identically. Non-IPv4 / malformed input returns false (fail closed).
fn is_mesh_source_addr(addr: &str) -> bool {
    let mut octets = addr.split('.');
    let (Some(a), Some(b), Some(c), Some(d), None) = (
        octets.next(),
        octets.next(),
        octets.next(),
        octets.next(),
        octets.next(),
    ) else {
        return false;
    };
    let parse = |s: &str| s.parse::<u8>().ok();
    match (parse(a), parse(b), parse(c), parse(d)) {
        (Some(a), Some(b), Some(_), Some(_)) => a == 100 && (64..=127).contains(&b),
        _ => false,
    }
}

/// True when the nft ruleset dump contains the rustynet exit NAT masquerade
/// rule: a `table ip rustynet_nat_g<N>` AND a `masquerade` verb somewhere in the
/// dump. Built by `apply_nat_forwarding` in rustynetd `phase10` (the
/// `rustynet_nat_g{generation}` ip table whose postrouting nat chain carries an
/// `oifname <egress> masquerade` rule). This matches the same two anchors the
/// live bash orchestrator asserts for an exit/admin firewall snapshot
/// (`table ip rustynet_nat_g[0-9]+` + `masquerade`). Fail closed: a dump with
/// the table but no masquerade verb, or vice-versa, returns false — a
/// non-NATing exit must not pass.
fn ruleset_has_rustynet_masquerade(ruleset: &str) -> bool {
    let has_nat_table = ruleset.lines().any(|line| {
        let t = line.trim();
        // `table ip rustynet_nat_g<N> {` — require a trailing digit so a bare
        // `rustynet_nat_g` prefix without a generation cannot match.
        if let Some(rest) = t.strip_prefix("table ip rustynet_nat_g") {
            rest.chars().next().is_some_and(|c| c.is_ascii_digit())
        } else {
            false
        }
    });
    let has_masquerade = ruleset
        .lines()
        .any(|line| line.split_whitespace().any(|tok| tok == "masquerade"));
    has_nat_table && has_masquerade
}

/// True when a single conntrack line (`conntrack -L` or `/proc/net/nf_conntrack`
/// row) shows a mesh-sourced (`100.64.0.0/10`) flow that has been NAT-translated
/// outbound. A conntrack row carries two tuples: the ORIGINAL direction
/// (`src=<client> dst=<dest> …`) and the REPLY direction (`src=<dest>
/// dst=<post-SNAT-src> …`). Under source-NAT/masquerade the reply `dst` (where
/// return traffic is sent — the exit's WAN address) differs from the original
/// `src` (the mesh client). We therefore require:
///   - the FIRST `src=` (original source) is a mesh address, AND
///   - a later `dst=` value (the reply destination) exists that differs from
///     that original source — i.e. the source was rewritten (translated).
///
/// Fail closed: a mesh-sourced but UNtranslated flow (reply dst == original src,
/// e.g. `[UNREPLIED]` with no SNAT yet, or intra-mesh traffic) returns false, as
/// does any non-mesh-sourced line.
fn conntrack_line_is_translated_mesh(line: &str) -> bool {
    // Collect the ordered list of src= and dst= values across both tuples.
    let mut srcs: Vec<&str> = Vec::new();
    let mut dsts: Vec<&str> = Vec::new();
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("src=") {
            srcs.push(v);
        } else if let Some(v) = tok.strip_prefix("dst=") {
            dsts.push(v);
        }
    }
    // Need both directions present (original + reply): >=2 src and >=2 dst.
    let (Some(orig_src), Some(reply_dst)) = (srcs.first(), dsts.get(1)) else {
        return false;
    };
    if !is_mesh_source_addr(orig_src) {
        return false;
    }
    // Translated iff the reply destination (post-SNAT source) differs from the
    // original source. Equal => no SNAT was applied (untranslated) => reject.
    orig_src != reply_dst
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

/// Minimal base64 decode that handles the standard alphabet (A-Z, a-z, 0-9, +, /).
/// Used for the 44-char `WireGuard` key (32 bytes → 44 base64 chars with `=` padding).
fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    // Filter out whitespace.
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_owned());
    }
    // Lookup table: ASCII byte → 6-bit value (64 = padding, 255 = invalid).
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

/// Assert that the collected artifact archive at `path` contains no key material.
/// This is a security invariant: `collect_artifacts` MUST NOT include
/// any file whose path contains `keys/`, ends with `.priv`, or ends with `.pem`.
fn verify_no_key_material(path: &std::path::Path) -> Result<(), AdapterError> {
    use std::process::Command;
    let output = Command::new("tar")
        .arg("-tzf")
        .arg(path.as_os_str())
        .output()
        .map_err(|err| AdapterError::Io {
            message: format!("tar -tzf failed: {err}"),
        })?;
    if !output.status.success() {
        return Err(AdapterError::Io {
            message: "tar -tzf on collected artifact archive returned non-zero".to_owned(),
        });
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        // GNU tar lists an empty directory as `.../keys/`. The directory name
        // is not key material; reject only payload entries below it. Other key
        // suffix checks remain fail-closed for files outside a `keys/` tree.
        if (entry.contains("keys/") && !entry.ends_with('/'))
            || entry.ends_with(".priv")
            || entry.ends_with(".pem")
            || entry.ends_with(".key")
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
    fn ping_diagnostic_reports_reachability_only_on_zero_exit() {
        let result = parse_ping_result(
            "100.75.227.10",
            "PING 100.75.227.10 (100.75.227.10) 56(84) bytes of data.\n\n__RUSTYNET_PING_EXIT=0\n",
        )
        .expect("well-formed diagnostic must parse");
        assert!(matches!(result, TrafficTestResult::Reachable));
    }

    #[test]
    fn ping_diagnostic_preserves_failure_output() {
        let result = parse_ping_result(
            "100.75.227.10",
            "PING 100.75.227.10 (100.75.227.10) 56(84) bytes of data.\nFrom 100.64.0.2 Destination Host Unreachable\n\n__RUSTYNET_PING_EXIT=1\n",
        )
        .expect("well-formed diagnostic must parse");
        let TrafficTestResult::Error(message) = result else {
            panic!("non-zero ping exit must be an error");
        };
        assert!(message.contains("exit 1"));
        assert!(message.contains("Destination Host Unreachable"));
    }

    #[test]
    fn ping_diagnostic_missing_or_invalid_marker_fails_closed() {
        assert!(parse_ping_result("100.75.227.10", "no marker").is_err());
        assert!(parse_ping_result("100.75.227.10", "__RUSTYNET_PING_EXIT=nope").is_err());
    }

    #[test]
    fn linux_nft_killswitch_reset_enumerates_all_rustynet_tables() {
        let cmd = LINUX_NFT_KILLSWITCH_RESET_COMMAND;
        // Guards on nft presence so a node without nft is a no-op.
        assert!(cmd.contains("command -v nft"));
        // Enumerates rustynet inet tables rather than a single fixed name, so a
        // leftover runtime table (e.g. rustynet_g1) cannot leave egress blocked.
        assert!(cmd.contains("nft list tables"));
        assert!(cmd.contains("$3 ~ /^rustynet/"));
        assert!(cmd.contains("nft delete table inet"));
        // Best-effort: tolerates absence at every privileged step.
        assert!(cmd.contains("|| true"));
        // Must NOT regress to deleting only the fixed `rustynet_boot` table.
        assert!(!cmd.contains("delete table inet rustynet_boot"));
        // Regression guard for the silent-no-op bug: the table list MUST be
        // captured into a variable first, then iterated with `for`. Piping
        // `… | while read t; do sudo nft delete …; done` is broken — the inner
        // `sudo` shares and drains the loop's stdin (the awk pipe), so `read`
        // sees nothing and no table is deleted. That left `rustynet_boot`
        // behind on every run until C2's assert_node_clean surfaced it.
        assert!(
            !cmd.contains("while read"),
            "reset must not pipe into `while read` (inner sudo drains the pipe)"
        );
        assert!(
            cmd.contains("rn_tables=$("),
            "reset must capture the table list into a variable first"
        );
        assert!(
            cmd.contains("for t in $rn_tables"),
            "reset must iterate the captured list with a `for` loop"
        );
    }

    #[test]
    fn linux_node_clean_probe_covers_nft_daemon_and_interface() {
        let p = LINUX_NODE_CLEAN_PROBE;
        // nft dimension: leftover rustynet inet tables.
        assert!(p.contains("nft list tables"));
        assert!(p.contains("$3 ~ /^rustynet/"));
        // daemon dimension: a still-running rustynetd.
        assert!(p.contains("pgrep -x rustynetd"));
        // interface dimension: leftover rustynet* links.
        assert!(p.contains("ip -o link show"));
        assert!(p.contains("/^rustynet/"));
        // Emits the three structured tokens the parser keys on.
        assert!(p.contains("nft=%s daemon=%s iface=%s"));
        // Tool-absence tolerant: a host without nft/ip is benign, not an error.
        assert!(p.contains("command -v nft"));
        assert!(p.contains("command -v ip"));
    }

    #[test]
    fn linux_interface_reset_enumerates_and_deletes_rustynet_links() {
        let cmd = LINUX_INTERFACE_RESET_COMMAND;
        // Guards on `ip` presence so a node without iproute2 is a no-op.
        assert!(cmd.contains("command -v ip"));
        // Enumerates rustynet* links rather than a single fixed `rustynet0`.
        assert!(cmd.contains("ip -o link show"));
        assert!(cmd.contains("/^rustynet/"));
        assert!(cmd.contains("ip link delete"));
        // Best-effort: tolerates absence/permission at every privileged step.
        assert!(cmd.contains("|| true"));
        // Captures the link list into a variable first, then iterates with a
        // `for` loop — same anti-stdin-drain shape as the nft reset.
        assert!(cmd.contains("rn_links=$("));
        assert!(cmd.contains("for link in $rn_links"));
        assert!(
            !cmd.contains("while read"),
            "reset must not pipe into `while read` (inner sudo drains the pipe)"
        );
    }

    #[test]
    fn parse_node_clean_probe_accepts_fully_clean_node() {
        assert!(parse_node_clean_probe("nft=- daemon=down iface=-\n").is_ok());
        // Empty-string sentinels (when the shell var expanded to nothing despite
        // the `:-` guard) are also benign.
        assert!(parse_node_clean_probe("nft= daemon=down iface=").is_ok());
        // Tolerates a leading banner/log line before the result line.
        assert!(parse_node_clean_probe("Warning: blah\nnft=- daemon=down iface=-").is_ok());
    }

    #[test]
    fn parse_node_clean_probe_reports_leftover_nft_table() {
        let err = parse_node_clean_probe("nft=rustynet_boot, daemon=down iface=-")
            .expect_err("leftover table must fail");
        let msg = err.to_string();
        assert!(msg.contains("node still dirty"));
        assert!(msg.contains("rustynet_boot"));
    }

    #[test]
    fn parse_node_clean_probe_reports_running_daemon() {
        let err = parse_node_clean_probe("nft=- daemon=up iface=-")
            .expect_err("running daemon must fail");
        assert!(
            err.to_string()
                .contains("rustynetd or rustynet-relay still running")
        );
    }

    #[test]
    fn parse_node_clean_probe_reports_leftover_interface() {
        let err = parse_node_clean_probe("nft=- daemon=down iface=rustynet0,")
            .expect_err("leftover interface must fail");
        let msg = err.to_string();
        assert!(msg.contains("interface"));
        assert!(msg.contains("rustynet0"));
    }

    #[test]
    fn parse_node_clean_probe_aggregates_multiple_dirty_dimensions() {
        let err = parse_node_clean_probe("nft=rustynet_g1, daemon=up iface=rustynet0,")
            .expect_err("multi-dirty must fail");
        let msg = err.to_string();
        assert!(msg.contains("rustynet_g1"));
        assert!(msg.contains("rustynetd or rustynet-relay still running"));
        assert!(msg.contains("rustynet0"));
    }

    #[test]
    fn parse_node_clean_probe_fails_closed_on_unrecognised_output() {
        // No result line at all → unknown state → fail closed, never pass.
        assert!(parse_node_clean_probe("").is_err());
        assert!(parse_node_clean_probe("ssh: connect timed out").is_err());
        // Result line missing a token (e.g. daemon=) → that dimension is
        // unknown → fail closed rather than assume clean.
        let err = parse_node_clean_probe("nft=- iface=-")
            .expect_err("missing daemon token must fail closed");
        assert!(err.to_string().contains("unrecognised") || err.to_string().contains("unknown"));
    }

    #[test]
    fn parse_node_clean_probe_treats_unknown_nft_token_as_dirty() {
        // The probe emits nft=unknown when nft IS present but the table query
        // failed (e.g. sudo -n denied) — an UNVERIFIABLE nft state must fail
        // closed, never pass as clean. (Regression for the Pair-1 P1-2 fix.)
        let err = parse_node_clean_probe("nft=unknown daemon=down iface=-")
            .expect_err("nft=unknown must fail closed");
        assert!(err.to_string().contains("unknown"), "{err}");
        let err = parse_node_clean_probe("nft=- daemon=down iface=unknown")
            .expect_err("iface=unknown must fail closed");
        assert!(err.to_string().contains("unknown"), "{err}");
    }

    #[test]
    fn clean_probe_and_reset_commands_prepend_sbin_to_path() {
        // Root cause of Pair-1 P1-2: `nft` is in /usr/sbin, which a non-login
        // SSH shell's PATH omits, so the `command -v nft` gate short-circuited —
        // the reset never ran and the clean probe fail-opened. Every command that
        // gates on `command -v nft`/`ip` MUST first put the sbin dirs on PATH.
        for cmd in [
            super::LINUX_NODE_CLEAN_PROBE,
            super::LINUX_NFT_KILLSWITCH_RESET_COMMAND,
            super::LINUX_INTERFACE_RESET_COMMAND,
        ] {
            assert!(
                cmd.contains("/usr/sbin:/sbin"),
                "command must prepend sbin to PATH so `command -v nft` finds it: {cmd}"
            );
        }
    }

    #[test]
    fn validate_ip_arg_accepts_valid_ipv4() {
        assert!(validate_ip_arg("10.0.0.1").is_ok());
        assert!(validate_ip_arg("192.168.1.100").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_valid_cidr() {
        assert!(validate_ip_arg("10.0.0.0/8").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_ipv6() {
        assert!(validate_ip_arg("fd00::1").is_ok());
    }

    #[test]
    fn validate_ip_arg_rejects_injection() {
        assert!(validate_ip_arg("10.0.0.1; rm -rf /").is_err());
        assert!(validate_ip_arg("$(whoami)").is_err());
        assert!(validate_ip_arg("10.0.0.1 && id").is_err());
    }

    // ── Active full-tunnel exit serving ────────────────────────────────────────

    #[test]
    fn activate_exit_serving_uses_constant_argv_over_daemon_socket() {
        // Argv-only safety + parity with the live bash orchestrator: the
        // advertise command must be all compile-time constants (no untrusted
        // interpolation), target the Linux daemon socket, and advertise the
        // default route over `sudo -n`.
        assert_eq!(LINUX_DAEMON_SOCKET, "/run/rustynet/rustynetd.sock");
        let script = format!(
            "sudo -n env RUSTYNET_DAEMON_SOCKET={LINUX_DAEMON_SOCKET} \
             /usr/local/bin/rustynet route advertise 0.0.0.0/0"
        );
        assert!(script.contains("sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock"));
        assert!(script.contains("/usr/local/bin/rustynet route advertise 0.0.0.0/0"));
    }

    #[test]
    fn is_mesh_source_addr_accepts_cgnat_range_only() {
        // In-range: 100.64.0.0 – 100.127.255.255.
        assert!(is_mesh_source_addr("100.64.0.1"));
        assert!(is_mesh_source_addr("100.100.5.9"));
        assert!(is_mesh_source_addr("100.127.255.254"));
        // Out of range: second octet below 64 or above 127, or wrong first octet.
        assert!(!is_mesh_source_addr("100.63.0.1"));
        assert!(!is_mesh_source_addr("100.128.0.1"));
        assert!(!is_mesh_source_addr("10.0.0.1"));
        assert!(!is_mesh_source_addr("1.1.1.1"));
        // Malformed / non-IPv4 fails closed.
        assert!(!is_mesh_source_addr("100.64.0"));
        assert!(!is_mesh_source_addr("100.64.0.1.5"));
        assert!(!is_mesh_source_addr("garbage"));
        assert!(!is_mesh_source_addr(""));
        assert!(!is_mesh_source_addr("100.300.0.1"));
    }

    #[test]
    fn ruleset_has_rustynet_masquerade_requires_nat_table_and_masquerade() {
        // Real-shape nft dump from an active Linux exit: the rustynet_nat_g<N> ip
        // table with a postrouting masquerade rule on the egress interface.
        let active = "\
table inet rustynet_g1 {
\tchain killswitch {
\t\ttype filter hook output priority filter; policy drop;
\t}
}
table ip rustynet_nat_g1 {
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"en0\" masquerade
\t}
}
";
        assert!(ruleset_has_rustynet_masquerade(active));
    }

    #[test]
    fn ruleset_has_rustynet_masquerade_fails_closed() {
        // Empty ruleset (no NAT applied) => not serving.
        assert!(!ruleset_has_rustynet_masquerade(""));
        // NAT table present but NO masquerade verb => not actually NATing.
        let table_no_masq = "\
table ip rustynet_nat_g2 {
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t}
}
";
        assert!(!ruleset_has_rustynet_masquerade(table_no_masq));
        // masquerade present but in a NON-rustynet table => not our exit NAT.
        let foreign_masq = "\
table ip other_nat {
\tchain postrouting {
\t\toifname \"en0\" masquerade
\t}
}
";
        assert!(!ruleset_has_rustynet_masquerade(foreign_masq));
        // The bare prefix without a generation digit must not match.
        let no_generation = "table ip rustynet_nat_g {\n\t\toifname \"en0\" masquerade\n}";
        assert!(!ruleset_has_rustynet_masquerade(no_generation));
    }

    #[test]
    fn conntrack_line_accepts_translated_mesh_source() {
        // A real `conntrack -L` line: a mesh client (100.64.0.3) connecting out
        // to 1.1.1.1; the reply tuple's dst is the exit's WAN address
        // (192.168.1.50) — i.e. the source was SNAT/masquerade-translated.
        let line = "tcp      6 117 SYN_SENT src=100.64.0.3 dst=1.1.1.1 sport=54321 \
            dport=443 [UNREPLIED] src=1.1.1.1 dst=192.168.1.50 sport=443 dport=54321 mark=0 use=1";
        assert!(conntrack_line_is_translated_mesh(line));
    }

    #[test]
    fn conntrack_line_accepts_proc_nf_conntrack_shape() {
        // /proc/net/nf_conntrack rows carry a leading `ipv4 2 tcp 6 …` prefix but
        // the same src=/dst= tuple layout.
        let line = "ipv4     2 tcp      6 431999 ESTABLISHED src=100.100.1.2 dst=8.8.8.8 \
            sport=40000 dport=443 src=8.8.8.8 dst=203.0.113.7 sport=443 dport=40000 \
            [ASSURED] mark=0 use=1";
        assert!(conntrack_line_is_translated_mesh(line));
    }

    #[test]
    fn conntrack_line_rejects_non_mesh_source() {
        // Original source is a LAN address, not a mesh (100.64/10) client.
        let line = "tcp      6 117 SYN_SENT src=192.168.1.10 dst=1.1.1.1 sport=54321 \
            dport=443 [UNREPLIED] src=1.1.1.1 dst=203.0.113.7 sport=443 dport=54321 use=1";
        assert!(!conntrack_line_is_translated_mesh(line));
    }

    #[test]
    fn conntrack_line_rejects_untranslated_mesh_flow() {
        // Mesh-sourced but the reply dst equals the original src (no SNAT applied
        // — e.g. intra-mesh or a flow the exit is merely routing, not NATing).
        // Must fail closed: this is NOT proof of egress via the exit's NAT.
        let line = "tcp      6 117 SYN_SENT src=100.64.0.3 dst=100.64.0.9 sport=54321 \
            dport=443 [UNREPLIED] src=100.64.0.9 dst=100.64.0.3 sport=443 dport=54321 use=1";
        assert!(!conntrack_line_is_translated_mesh(line));
    }

    #[test]
    fn conntrack_line_rejects_single_tuple_or_empty() {
        // A line with only the original tuple (no reply) cannot prove translation.
        let one_tuple = "tcp 6 117 SYN_SENT src=100.64.0.3 dst=1.1.1.1 sport=1 dport=443";
        assert!(!conntrack_line_is_translated_mesh(one_tuple));
        assert!(!conntrack_line_is_translated_mesh(""));
        assert!(!conntrack_line_is_translated_mesh(
            "garbage line with no tuples"
        ));
    }

    #[test]
    fn base64_decode_wireguard_key() {
        // A known 32-byte key encoded in base64.
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hex = decode_wireguard_pubkey_to_hex(encoded).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base64_decode_real_key() {
        // A valid 32-byte WireGuard public key in base64.
        let encoded = "6YIGkxJfmPNflshVeSPOc9LFNJrIcblSFQFGFhXqhg4=";
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_ok(), "failed: {result:?}");
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn base64_decode_rejects_wrong_length() {
        let encoded = "aGVsbG8="; // "hello" → 5 bytes
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_err(), "must reject non-32-byte key");
        assert!(
            result.unwrap_err().contains("32-byte"),
            "error must mention 32-byte"
        );
    }

    #[test]
    fn key_exclusion_rejects_keys_in_path() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Build a tar.gz with a dummy file at a keys/ path.
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        let mut f = std::fs::File::create(keys_dir.join("wireguard.priv")).unwrap();
        writeln!(f, "secret").unwrap();
        drop(f);

        let archive = NamedTempFile::new().unwrap();
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(archive.path())
            .arg("-C")
            .arg(dir.path())
            .arg("keys/wireguard.priv")
            .status()
            .unwrap();
        assert!(status.success());

        let result = verify_no_key_material(archive.path());
        assert!(result.is_err(), "must reject archive containing keys/ path");
        match result.unwrap_err() {
            AdapterError::KeyExclusionViolation { .. } => {}
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn key_exclusion_allows_empty_keys_directory_entry() {
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/lib/rustynet/keys")).unwrap();

        let archive = NamedTempFile::new().unwrap();
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(archive.path())
            .arg("-C")
            .arg(dir.path())
            .arg("var/lib/rustynet/keys")
            .status()
            .unwrap();
        assert!(status.success());

        let result = verify_no_key_material(archive.path());
        assert!(
            result.is_ok(),
            "empty key-directory metadata is not key material: {result:?}"
        );
    }

    #[test]
    fn check_ssh_reachable_fn_exists() {
        // Compilation test — function signature is valid.
        let _: fn(&NodeConnection) -> Result<(), AdapterError> = check_ssh_reachable;
    }

    #[test]
    fn key_exclusion_allows_non_key_paths() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
        writeln!(f, "log data").unwrap();
        drop(f);

        let archive = NamedTempFile::new().unwrap();
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(archive.path())
            .arg("-C")
            .arg(dir.path())
            .arg("daemon.log")
            .status()
            .unwrap();
        assert!(status.success());

        let result = verify_no_key_material(archive.path());
        assert!(result.is_ok(), "must allow non-key archive: {result:?}");
    }

    // ── userspace-shared tunnel liveness (wg show is empty for boringtun) ──────

    #[test]
    fn daemon_status_derives_active_tunnels_when_programmed_and_unrestricted() {
        // A healthy client (the r33 shape): not fail-closed, one programmed peer.
        let status = "node_id=debian-3 state=ExitActive restriction_mode=None \
                      path_programmed_mode=direct_programmed path_programmed_peer_count=1 \
                      reconcile_failures=0";
        let tunnels = super::tunnels_from_daemon_status(status);
        assert_eq!(tunnels.len(), 1, "one programmed peer -> one tunnel line");
        assert!(tunnels[0].contains("direct_programmed"));
    }

    #[test]
    fn daemon_status_derives_one_line_per_programmed_peer() {
        let status = "restriction_mode=None path_programmed_peer_count=3";
        assert_eq!(super::tunnels_from_daemon_status(status).len(), 3);
    }

    #[test]
    fn daemon_status_is_empty_when_fail_closed() {
        // restriction_mode != None means the daemon tore the dataplane down.
        let status = "state=FailClosed restriction_mode=Permanent path_programmed_peer_count=1";
        assert!(super::tunnels_from_daemon_status(status).is_empty());
    }

    #[test]
    fn daemon_status_is_empty_when_no_programmed_peers() {
        let status = "restriction_mode=None path_programmed_peer_count=0";
        assert!(super::tunnels_from_daemon_status(status).is_empty());
    }

    #[test]
    fn daemon_status_is_empty_when_keys_absent() {
        // An unparseable / empty status must fail closed, never a phantom tunnel.
        assert!(super::tunnels_from_daemon_status("").is_empty());
        assert!(super::tunnels_from_daemon_status("garbage output").is_empty());
    }
}
