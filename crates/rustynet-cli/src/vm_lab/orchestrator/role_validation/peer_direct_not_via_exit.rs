//! Peer-direct capture validator: proves that traffic from an exit-using
//! client to ANOTHER mesh node (entry/relay/aux/...) flows peer-to-peer and
//! NEVER reaches the exit, while the same client's internet-bound control
//! traffic DOES arrive on the exit's tunnel interface (the positive control
//! that keeps the capture honest — a silent capture proves nothing).
//!
//! Live proof: notes/PROOF-peer-direct-routing-2026-10-16.md (manual
//! lenovo-lab-264 run: peer-bound pings seen on client `rustynet0 Out` and on
//! the peer `rustynet0 In`, ZERO on the exit; control pings to 1.1.1.1 seen
//! arriving on the exit's `rustynet0 In`).
//!
//! Method (time-bounded, self-terminating): start `timeout`-wrapped tcpdump
//! captures on the exit (filter: peer + control + unused-mesh probe
//! addresses) and on the peer (filter: the client's mesh address), settle,
//! then from the client fire ICMP echoes at the peer mesh IP, a TCP connect
//! to a listener the stage opens on the peer's mesh address only, a UDP
//! datagram at the peer's mesh address, and a negative-space ICMP probe at an
//! unused mesh-CIDR address that belongs to no node. Finally the captures and
//! the listener transcript are fetched, the counts are evaluated
//! (`evaluate_peer_direct_failures`), and everything lands in the verdict
//! artifact. Capture files are removed after fetch — no residue.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellHost};
use std::sync::Arc;
use std::time::Duration;

/// RFC 5737 documentation-safe control target: proves the exit default route
/// is in use WITHOUT sending packets at a real internet host (the proof note
/// used 1.1.1.1; the live stage keeps the same assertion against TEST-NET-1).
pub(crate) const CONTROL_TARGET: &str = "192.0.2.1";

/// The tunnel interface every overlay packet must use (the daemon's own
/// constant; duplicated here only as the expected `ip route get` answer).
pub(crate) const TUNNEL_IFACE: &str = "rustynet0";

/// Negative-space probe seed: an address inside 100.64.0.0/10 that belongs to
/// no node. `unused_mesh_probe_addr_for` walks it backwards until it is
/// collision-free against the run's known mesh addresses.
pub(crate) const UNUSED_MESH_PROBE_SEED: &str = "100.127.255.254";

/// Ephemeral ports the probes use (never the daemon's, never well-known).
pub(crate) const PEER_TCP_PROBE_PORT: u16 = 23231;
pub(crate) const PEER_UDP_PROBE_PORT: u16 = 23232;

pub(crate) const TCP_PROBE_PAYLOAD: &[u8] = b"peer-direct-probe";

pub(crate) const CAPTURE_WINDOW_SECS: u64 = 30;
pub(crate) const CAPTURE_SETTLE_SECS: u64 = 2;
const CAPTURE_KILL_AFTER_SECS: u64 = 5;
const LISTENER_WINDOW_SECS: u64 = 25;

/// Readiness poll cadence for the peer listener (ms between `ss` probes).
const LISTENER_READY_POLL_MS: u64 = 200;
/// Total wall budget per spawn for the listener to reach LISTEN. A healthy
/// python3/nc bind takes milliseconds; 5s only ever elapses when the
/// listener is genuinely broken (katana-xnet-1250: spawn echo observed,
/// kernel socket never bound).
const LISTENER_READY_BUDGET_SECS: u64 = 5;
/// Inert argv marker appended to the python3 listener invocation so a
/// respawn's `pkill -f` can name exactly that process tree. The marker
/// lands in `sys.argv[1]`; the one-shot listener script never reads it.
const LISTENER_SPAWN_MARKER: &str = "peer_direct_listener_spawn_marker";

const EXIT_CAPTURE_REMOTE_PATH: &str = "/tmp/peer_direct_exit_capture.txt";
const PEER_CAPTURE_REMOTE_PATH: &str = "/tmp/peer_direct_peer_capture.txt";
const PEER_LISTENER_REMOTE_PATH: &str = "/tmp/peer_direct_peer_listener.txt";

/// The validator the peer-direct proof dispatches. Mirrors the exit-DNS
/// fail-closed dispatch shape: an uncovered platform maps to `None` and the
/// stage fails closed naming the desync instead of panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerDirectValidationKind {
    Linux,
}

pub(crate) fn peer_direct_runtime_implemented(platform: VmGuestPlatform) -> bool {
    validation_kind_for(platform).is_some()
}

pub(crate) fn validation_kind_for(platform: VmGuestPlatform) -> Option<PeerDirectValidationKind> {
    match platform {
        VmGuestPlatform::Linux => Some(PeerDirectValidationKind::Linux),
        VmGuestPlatform::Macos
        | VmGuestPlatform::Windows
        | VmGuestPlatform::Ios
        | VmGuestPlatform::Android => None,
    }
}

/// The addresses the proof runs against, resolved per-run.
#[derive(Debug, Clone)]
pub(crate) struct PeerDirectTargets {
    pub client_alias: String,
    pub exit_alias: String,
    pub peer_alias: String,
    pub client_ip: String,
    pub exit_ip: String,
    pub peer_ip: String,
    pub unused_probe_ip: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerDirectProbes {
    pub route_get_control_raw: String,
    pub route_get_peer_raw: String,
    pub ping_peer_rc: Option<i32>,
    pub tcp_ok: bool,
    pub tcp_reply_len: usize,
    pub udp_send_rc: Option<i32>,
    pub unused_ping_rc: Option<i32>,
    /// Exit-bound positive control (`ping` at [`CONTROL_TARGET`]). The rc is
    /// recorded only: the exit need not forward or answer TEST-NET traffic;
    /// the assertion is that it ARRIVES on the exit's tunnel interface.
    pub control_ping_rc: Option<i32>,
    pub listener_facility: String,
    pub listener_saw_payload: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerDirectCounts {
    /// Peer mesh address seen ANYWHERE on the exit (any iface, any direction).
    pub exit_saw_peer: usize,
    /// Unused mesh-CIDR address seen on the exit (= fall-through to the exit
    /// default route — the negative-space finding).
    pub exit_saw_unused: usize,
    /// Control target arriving INBOUND on the exit's tunnel iface.
    pub exit_saw_control_in_on_tunnel: usize,
    pub peer_icmp_echo_requests: usize,
    pub peer_tcp_probe_packets: usize,
    pub peer_udp_probe_packets: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerDirectReport {
    pub targets: PeerDirectTargets,
    pub exit_capture_filter: String,
    pub peer_capture_filter: String,
    pub probes: PeerDirectProbes,
    pub counts: PeerDirectCounts,
    pub exit_capture: String,
    pub peer_capture: String,
    pub listener_stdout: String,
    pub failures: Vec<String>,
    /// Non-failing observations (recorded in the verdict artifact only).
    pub observations: Vec<String>,
}

/// `ip route get <addr>` parsing: the interface the kernel would use. The
/// precondition demands this be the tunnel for BOTH the control target and
/// the peer — an exit not actually in use makes the whole proof vacuous and
/// must fail loud, not skip.
pub(crate) fn parse_route_dev(route_get_output: &str) -> Option<String> {
    for segment in route_get_output
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
    {
        if segment[0] == "dev" {
            return Some(segment[1].to_owned());
        }
    }
    None
}

/// Choose the negative-space probe address: starts at the seed and walks the
/// last octet DOWN until collision-free against every known mesh address.
/// Returns `None` when the whole tail of the /24 is taken (absurdly unlikely;
/// the stage fails closed on it rather than probing a known address).
pub(crate) fn unused_mesh_probe_addr_for(known_addrs: &[&str]) -> Option<String> {
    let seed: Vec<&str> = UNUSED_MESH_PROBE_SEED.split('.').collect();
    if seed.len() != 4 {
        return None;
    }
    for candidate in (1..=254).rev() {
        let addr = format!("{}.{}.{}.{}", seed[0], seed[1], seed[2], candidate);
        if !known_addrs.iter().any(|known| known == &addr) {
            return Some(addr);
        }
    }
    None
}

/// The exit-side BPF: the three addresses whose arrival (or non-arrival) is
/// the assertion. One argv token — the transport shell-quotes each element.
pub(crate) fn exit_capture_filter(peer_ip: &str, control: &str, unused: &str) -> String {
    format!("host {peer_ip} or host {control} or host {unused}")
}

pub(crate) fn peer_capture_filter(client_ip: &str) -> String {
    format!("host {client_ip}")
}

/// Inbound-line test for `tcpdump -i any` output: the Linux cooked-capture
/// direction marker appears as a standalone ` In ` token right after the
/// interface name (proof-note form: `... rustynet0 In IP 100.95.199.56 > ...`).
pub(crate) fn is_inbound_line(line: &str) -> bool {
    line.contains(" In ")
}

/// True when `line` mentions `addr` as a whole IPv4 address: the match is not
/// preceded by a digit or `.` and not followed by a digit (so `100.66.184.2`
/// never matches `100.66.184.214`). A trailing `.<port>` is allowed because
/// `tcpdump -nn` prints `addr.port`.
pub(crate) fn line_mentions_addr(line: &str, addr: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(found) = line[from..].find(addr) {
        let start = from + found;
        let end = start + addr.len();
        let before_ok =
            start == 0 || !(bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.');
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_digit();
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Lines that mention EVERY address in `addrs` (whole-address match). A
/// client->peer packet forwarded by the exit carries both inner addresses.
pub(crate) fn lines_mentioning_all_addrs<'a>(
    capture: &'a str,
    addrs: &'a [&'a str],
) -> impl Iterator<Item = &'a str> + 'a {
    capture
        .lines()
        .filter(move |line| addrs.iter().all(|addr| line_mentions_addr(line, addr)))
}

pub(crate) fn count_lines_with(capture: &str, needle: &str) -> usize {
    capture.lines().filter(|line| line.contains(needle)).count()
}

/// Lines matching EVERY needle, case-insensitively (tcpdump prints `ICMP`,
/// `UDP` capitalized and often no literal `tcp` token at all — TCP flows are
/// attributed by their numeric port instead).
pub(crate) fn count_lines_with_all(capture: &str, needles: &[&str]) -> usize {
    capture
        .lines()
        .filter(|line| {
            let hay = line.to_lowercase();
            needles
                .iter()
                .all(|needle| hay.contains(&needle.to_lowercase()))
        })
        .count()
}

pub(crate) fn count_inbound_lines_with_iface_and_addr(
    capture: &str,
    iface: &str,
    addr: &str,
) -> usize {
    capture
        .lines()
        .filter(|line| is_inbound_line(line) && line.contains(iface) && line.contains(addr))
        .count()
}

/// The pure verdict core: from the observed counts and probe results, the
/// list of invariant violations (empty = peer-direct proven). Unit-tested
/// against proof-note-shaped observations.
pub(crate) fn evaluate_peer_direct_failures(
    counts: &PeerDirectCounts,
    probes: &PeerDirectProbes,
    peer_ip: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    if counts.exit_saw_peer > 0 {
        failures.push(format!(
            "peer-bound traffic reached the exit: {peer_ip} seen on {} exit capture line(s) \
             — the peer-direct invariant is violated",
            counts.exit_saw_peer
        ));
    }
    if counts.exit_saw_control_in_on_tunnel == 0 {
        failures.push(format!(
            "silent capture: control traffic to {CONTROL_TARGET} was never seen arriving \
             inbound on the exit's {TUNNEL_IFACE} — without the positive control this capture \
             proves nothing"
        ));
    }
    if probes.ping_peer_rc != Some(0) {
        failures.push(format!(
            "client ICMP echo to peer {peer_ip} did not succeed (rc={:?})",
            probes.ping_peer_rc
        ));
    }
    if !probes.tcp_ok {
        failures.push(format!(
            "client TCP connect to peer {peer_ip}:{PEER_TCP_PROBE_PORT} failed"
        ));
    }
    if !probes.listener_saw_payload {
        failures.push(format!(
            "peer listener on {peer_ip}:{PEER_TCP_PROBE_PORT} did not report the probe payload"
        ));
    }
    if probes.udp_send_rc != Some(0) {
        failures.push(format!(
            "client UDP datagram to peer {peer_ip}:{PEER_UDP_PROBE_PORT} send failed (rc={:?})",
            probes.udp_send_rc
        ));
    }
    if counts.peer_icmp_echo_requests == 0 {
        failures.push(
            "peer capture saw no ICMP echo request from the client — peer did not receive \
             what the client sent"
                .to_owned(),
        );
    }
    if counts.peer_tcp_probe_packets == 0 {
        failures.push(format!(
            "peer capture saw no TCP probe packets on port {PEER_TCP_PROBE_PORT}"
        ));
    }
    if counts.peer_udp_probe_packets == 0 {
        failures.push(format!(
            "peer capture saw no UDP probe packets on port {PEER_UDP_PROBE_PORT}"
        ));
    }
    failures
}

/// Observations that do NOT fail the proof. The control plane installs only
/// per-peer host (/32) mesh routes and exit peers carry 0.0.0.0/0, so an
/// address inside the mesh CIDR that belongs to no node is selected by the
/// exit peer (longest-prefix match) BY DESIGN; this probe records whether
/// that happens, and the live run decides whether it should become a
/// requirement (a blackhole route would be a separate product change).
pub(crate) fn unused_mesh_observations(
    counts: &PeerDirectCounts,
    probes: &PeerDirectProbes,
    unused_probe_ip: &str,
) -> Vec<String> {
    let mut notes = Vec::new();
    if counts.exit_saw_unused > 0 {
        notes.push(format!(
            "unused mesh address {unused_probe_ip} was seen on the exit {} time(s) \
             (falls through to the exit default route; not a peer-direct failure)",
            counts.exit_saw_unused
        ));
    }
    if probes.unused_ping_rc == Some(0) {
        notes.push(format!(
            "unused mesh address {unused_probe_ip} was ANSWERED (ping rc=0)"
        ));
    }
    notes
}

fn run<S: AsRef<str>>(
    shell: &Arc<dyn RemoteShellHost>,
    argv: &[S],
) -> Result<RemoteExitStatus, String> {
    let owned: Vec<&str> = argv.iter().map(|arg| arg.as_ref()).collect();
    shell
        .run_argv(&owned, &[], &[])
        .map_err(|err| format!("run {owned:?} failed: {err}"))
}

/// Fire the whole bounded proof. Fails closed on: precondition violations
/// (exit route not in use), a missing listener facility, or any transport
/// error. NEVER interprets "no packets" as success — the positive control
/// guards that.
pub(crate) fn run_linux_peer_direct_not_via_exit(
    client_shell: Arc<dyn RemoteShellHost>,
    exit_shell: Arc<dyn RemoteShellHost>,
    peer_shell: Arc<dyn RemoteShellHost>,
    targets: &PeerDirectTargets,
    window_secs: u64,
    settle_secs: u64,
) -> Result<PeerDirectReport, String> {
    // ── Precondition (fail loud): the exit default route must actually be in
    // use — `ip route get` for the control target AND for the peer must both
    // resolve to the tunnel interface. A run without an active exit would
    // trivially show no peer traffic at the exit while proving nothing.
    let control_route = run(&client_shell, &["ip", "route", "get", CONTROL_TARGET])?;
    if control_route.code != 0 {
        return Err(format!(
            "precondition failed: `ip route get {CONTROL_TARGET}` exited {} on {}: {}",
            control_route.code,
            targets.client_alias,
            String::from_utf8_lossy(&control_route.stderr).trim()
        ));
    }
    let control_dev =
        parse_route_dev(&String::from_utf8_lossy(&control_route.stdout)).ok_or_else(|| {
            format!(
                "precondition failed: cannot parse a dev iface from `ip route get \
                 {CONTROL_TARGET}` output {:?}",
                String::from_utf8_lossy(&control_route.stdout).trim()
            )
        })?;
    if control_dev != TUNNEL_IFACE {
        return Err(format!(
            "precondition failed: {CONTROL_TARGET} resolves via {control_dev}, not the tunnel \
             iface {TUNNEL_IFACE} — the exit route is not in use, the proof would be vacuous"
        ));
    }
    let peer_route = run(
        &client_shell,
        &["ip", "route", "get", targets.peer_ip.as_str()],
    )?;
    if peer_route.code != 0 {
        return Err(format!(
            "precondition failed: `ip route get {}` exited {} on {}: {}",
            targets.peer_ip,
            peer_route.code,
            targets.client_alias,
            String::from_utf8_lossy(&peer_route.stderr).trim()
        ));
    }
    let peer_dev =
        parse_route_dev(&String::from_utf8_lossy(&peer_route.stdout)).ok_or_else(|| {
            format!(
                "precondition failed: cannot parse a dev iface from `ip route get {}` output",
                targets.peer_ip
            )
        })?;
    if peer_dev != TUNNEL_IFACE {
        return Err(format!(
            "precondition failed: peer {} resolves via {peer_dev}, not the tunnel iface \
             {TUNNEL_IFACE}",
            targets.peer_ip
        ));
    }

    let exit_capture_filter =
        exit_capture_filter(&targets.peer_ip, CONTROL_TARGET, &targets.unused_probe_ip);
    let peer_capture_filter = peer_capture_filter(&targets.client_ip);

    // ── Start both captures (self-terminating: `timeout` inside nohup).
    let kill_after = CAPTURE_KILL_AFTER_SECS;
    let timeout_secs = window_secs + kill_after;
    let exit_start_argv = [
        "sudo".to_owned(),
        "-n".to_owned(),
        "bash".to_owned(),
        "-c".to_owned(),
        format!(
            "rm -f {EXIT_CAPTURE_REMOTE_PATH}; nohup timeout --kill-after={kill_after} \
             {timeout_secs} tcpdump -i any -nn -tt -e -l '{exit_capture_filter}' \
             > {EXIT_CAPTURE_REMOTE_PATH} 2>&1 & echo PEER_DIRECT_CAPTURE_STARTED=1"
        ),
    ];
    let exit_started = run(&exit_shell, &exit_start_argv)?;
    if !String::from_utf8_lossy(&exit_started.stdout).contains("PEER_DIRECT_CAPTURE_STARTED=1") {
        return Err(format!(
            "capture on exit {} failed to start: {}",
            targets.exit_alias,
            String::from_utf8_lossy(&exit_started.stderr).trim()
        ));
    }
    let peer_start_argv = [
        "sudo".to_owned(),
        "-n".to_owned(),
        "bash".to_owned(),
        "-c".to_owned(),
        format!(
            "rm -f {PEER_CAPTURE_REMOTE_PATH}; nohup timeout --kill-after={kill_after} \
             {timeout_secs} tcpdump -i any -nn -tt -e -l '{peer_capture_filter}' \
             > {PEER_CAPTURE_REMOTE_PATH} 2>&1 & echo PEER_DIRECT_CAPTURE_STARTED=1"
        ),
    ];
    let peer_started = run(&peer_shell, &peer_start_argv)?;
    if !String::from_utf8_lossy(&peer_started.stdout).contains("PEER_DIRECT_CAPTURE_STARTED=1") {
        return Err(format!(
            "capture on peer {} failed to start: {}",
            targets.peer_alias,
            String::from_utf8_lossy(&peer_started.stderr).trim()
        ));
    }

    // ── Settle, then open the listener on the peer (mesh address ONLY).
    std::thread::sleep(Duration::from_secs(settle_secs));
    let facility_probe = run(
        &peer_shell,
        &[
            "sh",
            "-c",
            "command -v python3 >/dev/null 2>&1 && echo PY || (command -v nc >/dev/null 2>&1 && echo NC || echo NONE)",
        ],
    )?;
    let facility = String::from_utf8_lossy(&facility_probe.stdout)
        .trim()
        .to_owned();
    // The listener spawn race (katana-xnet-1250): the echo marker is
    // necessary but NOT sufficient — `echo PEER_DIRECT_LISTENER_STARTED=1`
    // is printed by the wrapper shell even when the listener binary dies
    // before bind(), and the old fixed sleep(1) then probed a port nothing
    // listened on (the kernel RST'd the SYN). Readiness is now proven from
    // the kernel socket table (`ss -tln`) before any probe fires, with ONE
    // bounded respawn and a fail-closed error carrying the listener's own
    // transcript. The UDP probe port (23232) deliberately has NO listener —
    // its "success" signal is the peer capture showing the datagram — so
    // only the TCP probe port is polled.
    let (listener_facility, spawn_argv, kill_pattern) = match facility.as_str() {
        "PY" => {
            let listener_body = format!(
                "import socket\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET, \
                 socket.SO_REUSEADDR, 1)\ns.bind(('{peer_ip}', {port}))\ns.listen(1)\n\
                 c,_=s.accept()\nd=c.recv(1024)\nprint('PEER_DIRECT_TCP_RECV:', \
                 d.decode(errors='replace'))\nc.close()\n",
                peer_ip = targets.peer_ip,
                port = PEER_TCP_PROBE_PORT,
            );
            let encoded = encode_base64(listener_body.as_bytes());
            let argv = [
                "sudo".to_owned(),
                "-n".to_owned(),
                "bash".to_owned(),
                "-c".to_owned(),
                format!(
                    "rm -f {PEER_LISTENER_REMOTE_PATH}; nohup timeout \
                     --kill-after={kill_after} {LISTENER_WINDOW_SECS} python3 -c \"import \
                     base64; exec(base64.b64decode('{encoded}').decode())\" \
                     {LISTENER_SPAWN_MARKER} \
                     > {PEER_LISTENER_REMOTE_PATH} 2>&1 & echo PEER_DIRECT_LISTENER_STARTED=1"
                ),
            ];
            (
                "python3".to_owned(),
                argv.to_vec(),
                LISTENER_SPAWN_MARKER.to_owned(),
            )
        }
        "NC" => {
            let argv = [
                "sudo".to_owned(),
                "-n".to_owned(),
                "bash".to_owned(),
                "-c".to_owned(),
                format!(
                    "rm -f {PEER_LISTENER_REMOTE_PATH}; nohup timeout \
                     --kill-after={kill_after} {LISTENER_WINDOW_SECS} nc -l -s {peer_ip} -p \
                     {port} > {PEER_LISTENER_REMOTE_PATH} 2>&1 & echo \
                     PEER_DIRECT_LISTENER_STARTED=1",
                    peer_ip = targets.peer_ip,
                    port = PEER_TCP_PROBE_PORT,
                ),
            ];
            (
                "nc".to_owned(),
                argv.to_vec(),
                format!("nc -l -s {} -p {PEER_TCP_PROBE_PORT}", targets.peer_ip),
            )
        }
        _ => {
            return Err(format!(
                "harness precondition failed: peer {} has neither python3 nor nc — no TCP \
                 listener can be opened for the peer-direct proof (failing closed)",
                targets.peer_alias
            ));
        }
    };

    // Necessary-but-not-sufficient spawn check: this only fails when the
    // spawn command itself never ran (sudo refusal, transport error); the
    // bind() readiness gate below is what actually protects the probes.
    let started = run(&peer_shell, &spawn_argv)?;
    if !String::from_utf8_lossy(&started.stdout).contains("PEER_DIRECT_LISTENER_STARTED=1") {
        return Err(format!(
            "{listener_facility} listener on peer {} failed to start: {}",
            targets.peer_alias,
            String::from_utf8_lossy(&started.stderr).trim()
        ));
    }

    if !wait_listener_ready(&peer_shell, PEER_TCP_PROBE_PORT, LISTENER_READY_BUDGET_SECS) {
        // One bounded respawn: a first spawn can lose the race against its
        // own rm/sudo environment; killing by the spawn marker and re-running
        // the IDENTICAL command is the only recovery that cannot mask a
        // peer-side fault (a second failure is reported, never absorbed).
        let _ = run(
            &peer_shell,
            &["sudo", "-n", "pkill", "-f", kill_pattern.as_str()],
        );
        let restarted = run(&peer_shell, &spawn_argv)?;
        let echo_seen =
            String::from_utf8_lossy(&restarted.stdout).contains("PEER_DIRECT_LISTENER_STARTED=1");
        if !echo_seen
            || !wait_listener_ready(&peer_shell, PEER_TCP_PROBE_PORT, LISTENER_READY_BUDGET_SECS)
        {
            // Fail closed WITH the evidence: name the socket-table reading
            // and attach the listener's own transcript, so the report shows
            // WHY nothing bound instead of a bare probe timeout.
            let last_ss = run(&peer_shell, &listener_readiness_argv(PEER_TCP_PROBE_PORT))
                .map(|s| {
                    format!(
                        "rc={} stdout={:?} stderr={:?}",
                        s.code,
                        clip_for_report(String::from_utf8_lossy(&s.stdout).trim(), 400),
                        clip_for_report(String::from_utf8_lossy(&s.stderr).trim(), 400)
                    )
                })
                .unwrap_or_else(|err| format!("ss probe transport failure: {err}"));
            let transcript =
                fetch_and_remove(&peer_shell, PEER_LISTENER_REMOTE_PATH).unwrap_or_default();
            return Err(format!(
                "listener-not-ready: {listener_facility} listener on peer {} never reached \
                 LISTEN on tcp/{} at {} after spawn and one respawn (spawn echo observed: \
                 {echo_seen}; ss now: {last_ss}); failing closed instead of firing probes at \
                 an unbound port. Listener transcript: {}",
                targets.peer_alias,
                PEER_TCP_PROBE_PORT,
                targets.peer_ip,
                clip_for_report(transcript.trim(), 4000)
            ));
        }
    }

    let mut probes = PeerDirectProbes {
        route_get_control_raw: String::from_utf8_lossy(&control_route.stdout)
            .trim()
            .to_owned(),
        route_get_peer_raw: String::from_utf8_lossy(&peer_route.stdout)
            .trim()
            .to_owned(),
        listener_facility,
        ..Default::default()
    };

    // ── Probes from the client.
    let ping = run(
        &client_shell,
        &["ping", "-c", "5", "-W", "2", targets.peer_ip.as_str()],
    );
    probes.ping_peer_rc = Some(ping.as_ref().map_or(-1, |status| status.code));

    match client_shell.tcp_send_recv(
        &format!("{}:{}", targets.peer_ip, PEER_TCP_PROBE_PORT),
        TCP_PROBE_PAYLOAD,
        Duration::from_secs(8),
    ) {
        Ok(reply) => {
            probes.tcp_ok = true;
            probes.tcp_reply_len = reply.len();
        }
        Err(_) => {
            probes.tcp_ok = false;
        }
    }

    let udp_send = run(
        &client_shell,
        &[
            "bash",
            "-c",
            &format!(
                "printf %s peer-direct-udp > /dev/udp/{}/{}",
                targets.peer_ip, PEER_UDP_PROBE_PORT
            ),
        ],
    );
    probes.udp_send_rc = Some(udp_send.as_ref().map_or(-1, |status| status.code));

    let unused_ping = run(
        &client_shell,
        &[
            "ping",
            "-c",
            "3",
            "-W",
            "2",
            targets.unused_probe_ip.as_str(),
        ],
    );
    probes.unused_ping_rc = Some(unused_ping.as_ref().map_or(-1, |status| status.code));

    // Positive control: exit-bound traffic from the client. The precondition
    // only ran `ip route get`, which sends nothing; without these packets the
    // exit capture can never contain the control and the proof always fails
    // as a silent capture. The rc is recorded only (the exit need not answer).
    let control_ping = run(
        &client_shell,
        &["ping", "-c", "3", "-W", "2", CONTROL_TARGET],
    );
    probes.control_ping_rc = Some(control_ping.as_ref().map_or(-1, |status| status.code));

    // ── Let the capture window finish, then fetch everything and clean up.
    let remaining = window_secs
        .saturating_sub(settle_secs)
        .saturating_sub(1)
        .max(1);
    std::thread::sleep(Duration::from_secs(remaining));

    let exit_capture = fetch_and_remove(&exit_shell, EXIT_CAPTURE_REMOTE_PATH)?;
    let peer_capture = fetch_and_remove(&peer_shell, PEER_CAPTURE_REMOTE_PATH)?;
    let listener_stdout = fetch_and_remove(&peer_shell, PEER_LISTENER_REMOTE_PATH)?;
    probes.listener_saw_payload =
        listener_stdout.contains(&*String::from_utf8_lossy(TCP_PROBE_PAYLOAD));

    let counts = PeerDirectCounts {
        // Only packets carrying BOTH the client and the peer address are a
        // client->peer flow forwarded by the exit. Exit<->peer traffic on
        // mesh addresses (gossip, control plane) is legitimate and must not
        // fail the proof.
        exit_saw_peer: lines_mentioning_all_addrs(
            &exit_capture,
            &[targets.client_ip.as_str(), targets.peer_ip.as_str()],
        )
        .count(),
        exit_saw_unused: exit_capture
            .lines()
            .filter(|line| line_mentions_addr(line, &targets.unused_probe_ip))
            .count(),
        exit_saw_control_in_on_tunnel: count_inbound_lines_with_iface_and_addr(
            &exit_capture,
            TUNNEL_IFACE,
            CONTROL_TARGET,
        ),
        peer_icmp_echo_requests: count_lines_with_all(
            &peer_capture,
            &[&targets.client_ip, "icmp", "echo request"],
        ),
        peer_tcp_probe_packets: count_lines_with_all(
            &peer_capture,
            &[&targets.client_ip, &format!(".{PEER_TCP_PROBE_PORT}:")],
        ),
        peer_udp_probe_packets: count_lines_with_all(
            &peer_capture,
            &[
                &targets.client_ip,
                "udp",
                &format!(".{PEER_UDP_PROBE_PORT}:"),
            ],
        ),
    };

    let mut failures = evaluate_peer_direct_failures(&counts, &probes, &targets.peer_ip);
    // Attach the first offending packet lines to the peer-leak failure so the
    // report names the packets, not just the count.
    if counts.exit_saw_peer > 0 {
        for line in lines_mentioning_all_addrs(
            &exit_capture,
            &[targets.client_ip.as_str(), targets.peer_ip.as_str()],
        )
        .take(3)
        {
            failures.push(format!("exit capture offending line: {line}"));
        }
    }
    let observations = unused_mesh_observations(&counts, &probes, &targets.unused_probe_ip);

    Ok(PeerDirectReport {
        targets: targets.clone(),
        exit_capture_filter,
        peer_capture_filter,
        probes,
        counts,
        exit_capture,
        peer_capture,
        listener_stdout,
        failures,
        observations,
    })
}

fn encode_base64(data: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(data)
}

fn fetch_and_remove(shell: &Arc<dyn RemoteShellHost>, remote_path: &str) -> Result<String, String> {
    let fetched = run(shell, &["sudo", "-n", "cat", remote_path])?;
    let _ = run(shell, &["sudo", "-n", "rm", "-f", remote_path]);
    Ok(String::from_utf8_lossy(&fetched.stdout).into_owned())
}

/// argv that asks the peer's kernel (via `ss`) whether anything is listening
/// on the probe port. Pure builder so tests pin the exact wire shape the
/// peer mock must be programmed for.
fn listener_readiness_argv(port: u16) -> Vec<String> {
    vec![
        "sudo".to_owned(),
        "-n".to_owned(),
        "ss".to_owned(),
        "-tln".to_owned(),
        format!("sport = :{port}"),
    ]
}

/// True when `ss -tln` output shows a bound LISTEN socket on `port`.
///
/// The `:port` suffix anchor (not a bare numeric suffix) prevents a shorter
/// port from matching a longer one, and the state token must be `LISTEN`, so
/// an accepted/closed socket never counts as ready. Header rows, malformed
/// short rows and empty output all read "not ready" — the caller keeps
/// polling until the budget expires and then fails closed.
fn parse_listener_ready(ss_stdout: &str, port: u16) -> bool {
    let suffix = format!(":{port}");
    ss_stdout.lines().any(|line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        tokens.len() >= 4
            && tokens[0].eq_ignore_ascii_case("listen")
            && tokens[3].ends_with(&suffix)
    })
}

/// Poll the peer's kernel socket table until the probe listener reaches
/// LISTEN, or the budget expires. This is the fix for the spawn-echo race:
/// the echo marker is emitted by the wrapper shell unconditionally, so
/// readiness must come from the kernel, not from the echo.
fn wait_listener_ready(shell: &Arc<dyn RemoteShellHost>, port: u16, budget_secs: u64) -> bool {
    let budget = Duration::from_secs(budget_secs);
    let interval = Duration::from_millis(LISTENER_READY_POLL_MS);
    let start = std::time::Instant::now();
    loop {
        if let Ok(status) = run(shell, &listener_readiness_argv(port)) {
            if status.code == 0
                && parse_listener_ready(&String::from_utf8_lossy(&status.stdout), port)
            {
                return true;
            }
        }
        if start.elapsed() >= budget {
            return false;
        }
        std::thread::sleep(interval);
    }
}

/// Char-boundary-safe clip for embedding remote transcripts in error
/// messages (lossy-decoded output may end mid multi-byte char).
fn clip_for_report(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        None => text,
        Some((boundary, _)) => &text[..boundary],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proof-note-shaped real capture lines (lenovo-lab-264, client
    /// 100.95.199.56, exit 100.123.229.22, peer entry 100.66.184.214).
    const EXIT_CAPTURE: &str = "\
15:41:02.113422 rustynet0  In IP 100.95.199.56 > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n\
15:41:02.115001 eth0   Out IP 100.123.229.22 > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n";
    const PEER_CAPTURE: &str = "\
15:41:01.900100 rustynet0  In IP 100.95.199.56 > 100.66.184.214: ICMP echo request, id 5, seq 1, length 64\n\
15:41:01.900900 rustynet0  In IP 100.95.199.56.41002 > 100.66.184.214.23231: Flags [S], seq 1\n\
15:41:01.901700 rustynet0  In IP 100.95.199.56.41003 > 100.66.184.214.23232: UDP, length 15\n";

    #[test]
    fn route_dev_parses_proof_note_route_line() {
        assert_eq!(
            parse_route_dev("1.1.1.1 dev rustynet0 table 51820 src 100.95.199.56 uid 0"),
            Some("rustynet0".to_owned())
        );
        assert_eq!(
            parse_route_dev("192.0.2.1 via 10.0.2.2 dev eth0"),
            Some("eth0".to_owned())
        );
        assert_eq!(
            parse_route_dev("RTNETLINK answers: Network is unreachable"),
            None
        );
    }

    #[test]
    fn unused_probe_addr_skips_known_addresses_and_stays_in_mesh_space() {
        let known = vec![
            "100.127.255.254",
            "100.95.199.56",
            "100.123.229.22",
            "100.66.184.214",
        ];
        let chosen = unused_mesh_probe_addr_for(&known).expect("collision-free addr");
        assert_eq!(chosen, "100.127.255.253");
        assert!(!known.contains(&chosen.as_str()));
        let all_taken: Vec<String> = (1..=254).map(|o| format!("100.127.255.{o}")).collect();
        let refs: Vec<&str> = all_taken.iter().map(|s| s.as_str()).collect();
        assert_eq!(unused_mesh_probe_addr_for(&refs), None);
    }

    #[test]
    fn capture_filters_are_single_tokens_naming_only_the_three_addresses() {
        let filter = exit_capture_filter("100.66.184.214", CONTROL_TARGET, "100.127.255.253");
        assert!(filter.contains("host 100.66.184.214"));
        assert!(filter.contains("host 192.0.2.1"));
        assert!(filter.contains("host 100.127.255.253"));
        assert_eq!(peer_capture_filter("100.95.199.56"), "host 100.95.199.56");
    }

    #[test]
    fn counts_read_proof_note_lines() {
        assert_eq!(count_lines_with(PEER_CAPTURE, "100.95.199.56"), 3);
        // Conjunction attribution: client AND protocol AND port.
        assert_eq!(
            count_lines_with_all(PEER_CAPTURE, &["100.95.199.56", "icmp", "echo request"]),
            1
        );
        assert_eq!(
            count_lines_with_all(PEER_CAPTURE, &["100.95.199.56", "23231"]),
            1,
            "TCP flows carry no literal `tcp` token — attributed by the probe port"
        );
        assert_eq!(
            count_lines_with_all(PEER_CAPTURE, &["100.95.199.56", "udp", "23232"]),
            1
        );
        assert_eq!(
            count_lines_with_all(PEER_CAPTURE, &["100.95.199.56", "udp", "23231"]),
            0,
            "wrong port must not be attributed to the UDP probe"
        );
        assert_eq!(
            count_inbound_lines_with_iface_and_addr(EXIT_CAPTURE, "rustynet0", "192.0.2.1"),
            1
        );
        assert_eq!(
            count_inbound_lines_with_iface_and_addr(EXIT_CAPTURE, "eth0", "192.0.2.1"),
            0,
            "the eth0 Out re-emission is not an inbound tunnel arrival"
        );
    }

    fn clean_probes() -> PeerDirectProbes {
        PeerDirectProbes {
            route_get_control_raw: "192.0.2.1 dev rustynet0 table 51820".to_owned(),
            route_get_peer_raw: "100.66.184.214 dev rustynet0 table 51820".to_owned(),
            ping_peer_rc: Some(0),
            tcp_ok: true,
            tcp_reply_len: 4,
            udp_send_rc: Some(0),
            unused_ping_rc: Some(1),
            control_ping_rc: Some(1),
            listener_facility: "python3".to_owned(),
            listener_saw_payload: true,
        }
    }

    fn clean_counts() -> PeerDirectCounts {
        PeerDirectCounts {
            exit_saw_peer: 0,
            exit_saw_unused: 0,
            exit_saw_control_in_on_tunnel: 3,
            peer_icmp_echo_requests: 5,
            peer_tcp_probe_packets: 2,
            peer_udp_probe_packets: 1,
        }
    }

    #[test]
    fn clean_observation_has_no_failures() {
        let failures =
            evaluate_peer_direct_failures(&clean_counts(), &clean_probes(), "100.66.184.214");
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn exit_sees_peer_traffic_fails_with_the_reason() {
        let mut counts = clean_counts();
        counts.exit_saw_peer = 2;
        let failures = evaluate_peer_direct_failures(&counts, &clean_probes(), "100.66.184.214");
        assert!(
            failures.iter().any(|f| f.contains("reached the exit")),
            "{failures:?}"
        );
    }

    #[test]
    fn silent_capture_fails_even_when_everything_else_looks_clean() {
        let mut counts = clean_counts();
        counts.exit_saw_control_in_on_tunnel = 0;
        let failures = evaluate_peer_direct_failures(&counts, &clean_probes(), "100.66.184.214");
        assert!(
            failures.iter().any(|f| f.contains("silent capture")),
            "{failures:?}"
        );
    }

    #[test]
    fn peer_did_not_receive_fails() {
        let mut counts = clean_counts();
        counts.peer_icmp_echo_requests = 0;
        let failures = evaluate_peer_direct_failures(&counts, &clean_probes(), "100.66.184.214");
        assert!(
            failures
                .iter()
                .any(|f| f.contains("peer capture saw no ICMP echo request")),
            "{failures:?}"
        );
    }

    #[test]
    fn unused_mesh_fall_through_is_an_observation_not_a_failure() {
        let mut counts = clean_counts();
        counts.exit_saw_unused = 3;
        let mut probes = clean_probes();
        probes.unused_ping_rc = Some(0);
        let failures = evaluate_peer_direct_failures(&counts, &probes, "100.66.184.214");
        assert!(failures.is_empty(), "{failures:?}");
        let notes = unused_mesh_observations(&counts, &probes, "100.127.255.253");
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(unused_mesh_observations(&clean_counts(), &clean_probes(), "x").is_empty());
    }

    #[test]
    fn whole_address_matching_rejects_prefix_and_suffix_collisions() {
        assert!(line_mentions_addr(
            "In IP 100.66.184.214 > 1.2.3.4",
            "100.66.184.214"
        ));
        assert!(line_mentions_addr(
            "IP 100.66.184.214.23231: Flags",
            "100.66.184.214"
        ));
        assert!(!line_mentions_addr("IP 100.66.184.214 > x", "100.66.184.2"));
        assert!(!line_mentions_addr("IP 9100.66.184.2 > x", "100.66.184.2"));
        assert!(!line_mentions_addr("IP 1.2.3.4 > x", ""));
    }

    #[test]
    fn exit_peer_gossip_is_not_a_leak_but_client_to_peer_is() {
        let gossip = "1.0 rustynet0 Out IP 100.123.229.22.7000 > 100.66.184.214.7000: UDP, length 90\n\
                      1.1 rustynet0 In  IP 100.66.184.214.7000 > 100.123.229.22.7000: UDP, length 90\n";
        let none: Vec<&str> =
            lines_mentioning_all_addrs(gossip, &["100.95.199.56", "100.66.184.214"]).collect();
        assert!(none.is_empty(), "{none:?}");
        let leak = format!(
            "{gossip}2.0 rustynet0 Out IP 100.95.199.56 > 100.66.184.214: ICMP echo request\n"
        );
        let hits: Vec<&str> =
            lines_mentioning_all_addrs(&leak, &["100.95.199.56", "100.66.184.214"]).collect();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn every_probe_channel_is_required() {
        for mutator in [
            |p: &mut PeerDirectProbes| p.ping_peer_rc = Some(1),
            |p: &mut PeerDirectProbes| p.tcp_ok = false,
            |p: &mut PeerDirectProbes| p.listener_saw_payload = false,
            |p: &mut PeerDirectProbes| p.udp_send_rc = Some(1),
        ] {
            let mut probes = clean_probes();
            mutator(&mut probes);
            let failures =
                evaluate_peer_direct_failures(&clean_counts(), &probes, "100.66.184.214");
            assert!(!failures.is_empty(), "mutated probes must fail: {probes:?}");
        }
        // Every captured channel on the peer must also be required: a capture
        // that missed the ICMP, TCP, or UDP probe fails the proof (a silent
        // capture must never count as a pass).
        for mutator in [
            |c: &mut PeerDirectCounts| c.peer_icmp_echo_requests = 0,
            |c: &mut PeerDirectCounts| c.peer_tcp_probe_packets = 0,
            |c: &mut PeerDirectCounts| c.peer_udp_probe_packets = 0,
        ] {
            let mut counts = clean_counts();
            mutator(&mut counts);
            let failures =
                evaluate_peer_direct_failures(&counts, &clean_probes(), "100.66.184.214");
            assert!(
                !failures.is_empty(),
                "missing peer capture channel must fail: {counts:?}"
            );
        }
    }

    #[test]
    fn validation_kind_never_panics_on_ungated_platforms() {
        assert_eq!(
            validation_kind_for(VmGuestPlatform::Linux),
            Some(PeerDirectValidationKind::Linux)
        );
        for uncovered in [
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
            VmGuestPlatform::Ios,
            VmGuestPlatform::Android,
        ] {
            assert_eq!(validation_kind_for(uncovered), None);
            assert!(!peer_direct_runtime_implemented(uncovered));
        }
        assert!(peer_direct_runtime_implemented(VmGuestPlatform::Linux));
    }

    #[test]
    fn listener_body_base64_roundtrip_matches_remote_shell_alphabet() {
        let body = format!("bind('{}', {})", "100.66.184.214", PEER_TCP_PROBE_PORT);
        let encoded = encode_base64(body.as_bytes());
        assert!(!encoded.contains('\n'));
        assert!(encoded.len() % 4 == 0);
        assert!(encoded.ends_with('=') == (body.len() % 3 != 0));
    }

    // ---- end-to-end driver tests over scripted shells (no ssh) -----------

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const CLIENT_IP: &str = "100.95.199.56";
    const PEER_IP: &str = "100.66.184.214";
    const EXIT_IP: &str = "100.123.229.22";

    fn ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn driver_targets() -> PeerDirectTargets {
        PeerDirectTargets {
            client_alias: "c".to_owned(),
            exit_alias: "e".to_owned(),
            peer_alias: "p".to_owned(),
            client_ip: CLIENT_IP.to_owned(),
            exit_ip: EXIT_IP.to_owned(),
            peer_ip: PEER_IP.to_owned(),
            unused_probe_ip: "100.127.255.253".to_owned(),
        }
    }

    /// Scripted trio. `exit_capture` / `peer_capture` / `listener` are what
    /// the fetches return.
    fn run_driver(
        exit_capture: &str,
        peer_capture: &str,
        listener: &str,
    ) -> (PeerDirectReport, Arc<MockShellHost>) {
        let client = Arc::new(MockShellHost::new());
        client.program_run_response(
            &["ip", "route", "get", CONTROL_TARGET],
            ok("192.0.2.1 dev rustynet0 table 51820 src 100.95.199.56"),
        );
        client.program_run_response(
            &["ip", "route", "get", PEER_IP],
            ok("100.66.184.214 dev rustynet0 src 100.95.199.56"),
        );
        client.program_default_run_response(ok(""));
        client.program_tcp_response(&format!("{PEER_IP}:{PEER_TCP_PROBE_PORT}"), Vec::new());

        let exit = Arc::new(MockShellHost::new());
        exit.program_default_run_response(ok("PEER_DIRECT_CAPTURE_STARTED=1"));
        exit.program_run_response(
            &["sudo", "-n", "cat", EXIT_CAPTURE_REMOTE_PATH],
            ok(exit_capture),
        );

        let peer = Arc::new(MockShellHost::new());
        peer.program_default_run_response(ok(
            "PEER_DIRECT_CAPTURE_STARTED=1 PEER_DIRECT_LISTENER_STARTED=1",
        ));
        peer.program_run_response(
            &[
                "sh",
                "-c",
                "command -v python3 >/dev/null 2>&1 && echo PY || (command -v nc >/dev/null 2>&1 && echo NC || echo NONE)",
            ],
            ok("PY"),
        );
        peer.program_run_response(
            &[
                "sudo",
                "-n",
                "ss",
                "-tln",
                &format!("sport = :{PEER_TCP_PROBE_PORT}"),
            ],
            ok("LISTEN 0 128 100.66.184.214:23231 0.0.0.0:*"),
        );
        peer.program_run_response(
            &["sudo", "-n", "cat", PEER_CAPTURE_REMOTE_PATH],
            ok(peer_capture),
        );
        peer.program_run_response(
            &["sudo", "-n", "cat", PEER_LISTENER_REMOTE_PATH],
            ok(listener),
        );

        let report =
            run_linux_peer_direct_not_via_exit(client.clone(), exit, peer, &driver_targets(), 1, 0)
                .expect("driver runs");
        (report, client)
    }

    const CONTROL_ON_EXIT: &str =
        "1.0 rustynet0 In  IP 100.95.199.56 > 192.0.2.1: ICMP echo request, id 1, seq 1\n";
    const LISTENER_OK: &str = "PEER_DIRECT_TCP_RECV: peer-direct-probe\n";

    #[test]
    fn driver_sends_the_exit_bound_positive_control_from_the_client() {
        let (_report, client) = run_driver(CONTROL_ON_EXIT, PEER_CAPTURE, LISTENER_OK);
        let sent_control = client.run_log().iter().any(|call| {
            call.argv.first().map(String::as_str) == Some("ping")
                && call.argv.last().map(String::as_str) == Some(CONTROL_TARGET)
        });
        assert!(
            sent_control,
            "no packet was ever sent at {CONTROL_TARGET}; the capture could never see the control"
        );
    }

    #[test]
    fn driver_passes_when_exit_sees_only_control_and_its_own_peer_gossip() {
        let gossip =
            "1.5 rustynet0 Out IP 100.123.229.22.7000 > 100.66.184.214.7000: UDP, length 90\n";
        let exit_capture = format!("{CONTROL_ON_EXIT}{gossip}");
        let (report, _client) = run_driver(&exit_capture, PEER_CAPTURE, LISTENER_OK);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.counts.exit_saw_peer, 0);
        assert_eq!(report.counts.exit_saw_control_in_on_tunnel, 1);
    }

    #[test]
    fn driver_fails_when_client_to_peer_traffic_is_seen_on_the_exit() {
        let leak = "2.0 rustynet0 In  IP 100.95.199.56 > 100.66.184.214: ICMP echo request\n";
        let exit_capture = format!("{CONTROL_ON_EXIT}{leak}");
        let (report, _client) = run_driver(&exit_capture, PEER_CAPTURE, LISTENER_OK);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("reached the exit")),
            "{:?}",
            report.failures
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("exit capture offending line")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn driver_fails_as_silent_capture_without_control_on_the_exit() {
        let (report, _client) = run_driver("", PEER_CAPTURE, LISTENER_OK);
        assert!(
            report.failures.iter().any(|f| f.contains("silent capture")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn driver_requires_the_probe_payload_in_the_listener_transcript() {
        let (report, _client) = run_driver(CONTROL_ON_EXIT, PEER_CAPTURE, "");
        assert!(!report.probes.listener_saw_payload);
        assert!(!report.failures.is_empty());
        // A netcat listener prints the raw payload with no marker.
        let (report, _client) = run_driver(CONTROL_ON_EXIT, PEER_CAPTURE, "peer-direct-probe");
        assert!(report.probes.listener_saw_payload, "{:?}", report.failures);
    }

    // ---- listener readiness race (katana-xnet-1250) ----------------------

    #[test]
    fn listener_readiness_argv_is_the_exact_kernel_probe() {
        assert_eq!(
            listener_readiness_argv(PEER_TCP_PROBE_PORT),
            vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "ss".to_owned(),
                "-tln".to_owned(),
                "sport = :23231".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_listener_ready_reads_real_ss_output() {
        let real = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
                    LISTEN 0      128        100.66.184.214:23231 0.0.0.0:*\n";
        assert!(parse_listener_ready(real, PEER_TCP_PROBE_PORT));
        // No header needed; a bare matching row is enough.
        assert!(parse_listener_ready(
            "LISTEN 0 128 0.0.0.0:23231 0.0.0.0:*",
            PEER_TCP_PROBE_PORT
        ));
        // IPv6-form local addresses anchor on the same :port suffix.
        assert!(parse_listener_ready(
            "LISTEN 0 128 [::]:23231 [::]:*",
            PEER_TCP_PROBE_PORT
        ));
        // State token matching is case-insensitive (some ss builds).
        assert!(parse_listener_ready(
            "listen 0 128 0.0.0.0:23231 0.0.0.0:*",
            PEER_TCP_PROBE_PORT
        ));
    }

    #[test]
    fn parse_listener_ready_rejects_empty_header_and_malformed_output() {
        assert!(!parse_listener_ready("", PEER_TCP_PROBE_PORT));
        assert!(!parse_listener_ready(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port",
            PEER_TCP_PROBE_PORT
        ));
        // Short/malformed rows never panic and never count as ready.
        assert!(!parse_listener_ready("LISTEN 0 128", PEER_TCP_PROBE_PORT));
        assert!(!parse_listener_ready("garbage", PEER_TCP_PROBE_PORT));
    }

    #[test]
    fn parse_listener_ready_rejects_suffix_collisions_and_non_listen_states() {
        // A DIFFERENT port whose decimal text ends with the probe port's
        // digits must not match — the `:port` anchor is the guard.
        assert!(!parse_listener_ready(
            "LISTEN 0 128 0.0.0.0:2323 0.0.0.0:*",
            PEER_TCP_PROBE_PORT
        ));
        assert!(!parse_listener_ready(
            "LISTEN 0 128 0.0.0.0:123231 0.0.0.0:*",
            PEER_TCP_PROBE_PORT
        ));
        // Accepted/closed sockets on the right port are NOT readiness.
        assert!(!parse_listener_ready(
            "ESTAB 0 0 100.66.184.214:23231 100.95.199.56:41002",
            PEER_TCP_PROBE_PORT
        ));
        assert!(!parse_listener_ready(
            "CLOSED 0 0 100.66.184.214:23231 0.0.0.0:*",
            PEER_TCP_PROBE_PORT
        ));
    }

    #[test]
    fn clip_for_report_clips_on_char_boundaries() {
        assert_eq!(clip_for_report("", 10), "");
        assert_eq!(clip_for_report("short", 10), "short");
        let long = "x".repeat(500);
        assert_eq!(clip_for_report(&long, 300).len(), 300);
        // Multi-byte characters must never split a char (would panic).
        let multibyte = "é".repeat(400);
        let clipped = clip_for_report(&multibyte, 300);
        assert_eq!(clipped.chars().count(), 300);
        assert_eq!(clipped.len(), 600);
    }

    #[test]
    fn wait_listener_ready_polls_until_the_kernel_agrees() {
        // Ready on the first poll: zero added wall time.
        let peer = Arc::new(MockShellHost::new());
        peer.program_run_response(
            &[
                "sudo",
                "-n",
                "ss",
                "-tln",
                &format!("sport = :{PEER_TCP_PROBE_PORT}"),
            ],
            ok("LISTEN 0 128 100.66.184.214:23231 0.0.0.0:*"),
        );
        let start = std::time::Instant::now();
        let peer_dyn: Arc<dyn RemoteShellHost> = peer.clone();
        assert!(wait_listener_ready(&peer_dyn, PEER_TCP_PROBE_PORT, 5));
        assert!(start.elapsed().as_secs() < 5, "must return on first poll");

        // Never ready + zero budget: exactly one poll, then fail.
        let peer = Arc::new(MockShellHost::new());
        peer.program_default_run_response(ok("not-listening"));
        let peer_dyn: Arc<dyn RemoteShellHost> = peer.clone();
        assert!(!wait_listener_ready(&peer_dyn, PEER_TCP_PROBE_PORT, 0));
        assert_eq!(peer.run_log().len(), 1);
    }

    #[test]
    fn driver_consults_the_kernel_socket_table_before_probing() {
        let (_report, client) = run_driver(CONTROL_ON_EXIT, PEER_CAPTURE, LISTENER_OK);
        // Sanity: the client really did probe in the happy path.
        assert!(
            client
                .run_log()
                .iter()
                .any(|call| call.argv.first().map(String::as_str) == Some("ping"))
        );
    }

    #[test]
    fn driver_fails_closed_when_the_listener_never_binds() {
        // Reproduces the katana-xnet-1250 shape: the spawn echo IS observed
        // (the wrapper prints it unconditionally) but the kernel socket
        // table never shows a LISTEN socket. The driver must fail closed
        // naming listener-not-ready WITH the listener transcript, and must
        // never fire the client probes at the unbound port.
        let client = Arc::new(MockShellHost::new());
        client.program_run_response(
            &["ip", "route", "get", CONTROL_TARGET],
            ok("192.0.2.1 dev rustynet0 table 51820 src 100.95.199.56"),
        );
        client.program_run_response(
            &["ip", "route", "get", PEER_IP],
            ok("100.66.184.214 dev rustynet0 src 100.95.199.56"),
        );
        let exit = Arc::new(MockShellHost::new());
        exit.program_default_run_response(ok("PEER_DIRECT_CAPTURE_STARTED=1"));
        let peer = Arc::new(MockShellHost::new());
        // The echo string doubles as the default response: it proves the
        // echo check passes while `ss` keeps answering "nothing bound".
        peer.program_default_run_response(ok(
            "PEER_DIRECT_CAPTURE_STARTED=1 PEER_DIRECT_LISTENER_STARTED=1",
        ));
        peer.program_run_response(
            &[
                "sh",
                "-c",
                "command -v python3 >/dev/null 2>&1 && echo PY || (command -v nc >/dev/null 2>&1 && echo NC || echo NONE)",
            ],
            ok("PY"),
        );
        peer.program_run_response(
            &["sudo", "-n", "cat", PEER_LISTENER_REMOTE_PATH],
            ok("python3: boom"),
        );

        let err =
            run_linux_peer_direct_not_via_exit(client.clone(), exit, peer, &driver_targets(), 1, 0)
                .expect_err("must fail closed when nothing binds");
        assert!(err.contains("listener-not-ready"), "{err}");
        assert!(err.contains("python3: boom"), "{err}");
        assert!(err.contains("tcp/23231"), "{err}");
        // No probe was ever fired at the unbound port: the only client
        // traffic is the two route preconditions.
        assert!(
            !client
                .run_log()
                .iter()
                .any(|call| call.argv.first().map(String::as_str) == Some("ping")),
            "probes must not fire before readiness is proven"
        );
        assert!(client.tcp_log().is_empty());
    }
}
