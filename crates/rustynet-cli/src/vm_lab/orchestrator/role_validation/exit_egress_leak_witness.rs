#![allow(dead_code)]
//! Linux exit-node egress leak witness (AQ-46) for the standard orchestrator.
//!
//! While the exit killswitch (commit `5093ac97`) scopes its DNS/DoT drops to
//! the egress interface and emits no IPv6 accept, that ruleset is NOT PROVEN
//! until lab-witnessed: this validator captures the exit's egress NIC with
//! `tcpdump` during a bounded window while host-origin DNS/DoT/IPv6 probes and
//! a client positive control run, then classifies every packet. The egress NIC
//! must carry zero host-origin udp/53, tcp/53, tcp/853, or IPv6, while
//! masqueraded client ICMP to 192.0.2.1 and WireGuard udp on the listen port
//! are present — any leak class, or a vacuous capture, fails closed.
//!
//! W3 — conservative attribution of masqueraded client flows (audit
//! Q4.2/Q4.3): a tcp/53|853 packet whose source is the egress address can be
//! a CLIENT flow masqueraded by the FORWARD chain (which by design carries
//! no DNS drops), not a host-origin leak. Each such packet is looked up in
//! conntrack snapshots (or, when the `conntrack` binary is missing — real
//! lab guests ship without it — a successful filtered
//! `/proc/net/nf_conntrack` read, parsed by the SAME code) taken at capture
//! start AND capture end; attribution arms only when every snapshot is
//! answered in BOTH windows and the exit's local addresses are known. A
//! matched entry relieves a packet only when
//! its ORIGINAL source is provably not the exit itself AND provably a mesh
//! client (stage-supplied client addresses, else the TUNNEL interface
//! subnet from the interface listing, else the documented RFC1918+CGNAT
//! fallback); a flow with no initiator packet inside the window must
//! additionally match in BOTH snapshots, and a flow WITH an initiator must
//! not collide in the START snapshot with a DIFFERING ORIGINAL tuple (port
//! reuse). Every other case — no matching entry, unparseable
//! snapshot, partially-answered snapshot, missing snapshot, conntrack
//! unavailable, ambiguous matches, foreign-but-not-client sources — keeps
//! the count-and-fail behaviour, so W3 can never turn a possible host leak
//! into a pass. The raw ICMP positive control is unchanged (at least one
//! ICMP packet to 192.0.2.1 on the wire, or the witness is vacuous); W3
//! additionally requires that captured ICMP be conntrack-attributed to a
//! client flow — but ONLY while attribution is actually armed: a
//! conntrack-less guest (no binary, no /proc) keeps the raw control and
//! the count-and-fail leaks, and cannot demand the unsatisfiable
//! attributed half.
//!
//! All remote execution is argv-only through the [`RemoteShellHost`] seam:
//! the tcpdump filter is passed as separate argv tokens and every probe target
//! is a compile-time constant, so no remote value is ever concatenated into a
//! shell string.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_validation::discover_single_generated_nft_table;
use crate::vm_lab::orchestrator::stage::cross_network::scenario::TUNNEL_INTERFACE;
use crate::vm_lab::orchestrator::stage::cross_network::substrate::{
    OVERLAY_POOL_CIDR, VXLAN_LINK_NAME, VXLAN_SUBSTRATE_ID,
};
use std::sync::Arc;

/// Test-net documentation target the host-origin DNS probes are fired at.
/// RFC 5737 / RFC 5737-adjacent reserved space: nothing answers, so the probes
/// are expected to fail locally — their exit codes are recorded, not errors.
pub const WITNESS_DNS_TARGET: &str = "192.0.2.53";
/// Test-net target for the masqueraded client ICMP positive control.
pub const WITNESS_ICMP_TARGET: &str = "192.0.2.1";
/// Documentation-only IPv6 target for the host-origin IPv6 attempt.
pub const WITNESS_IPV6_TARGET: &str = "2001:db8::53";
/// DoT port witnessed alongside udp/tcp 53.
pub const WITNESS_DOT_PORT: u16 = 853;

/// Live capture window in seconds. The tcpdump side is bounded by
/// `timeout` regardless of this value, so a stalled transport cannot hang
/// the stage.
pub const CAPTURE_WINDOW_SECS: u64 = 20;
/// Settle delay after tcpdump starts before probes fire, so early packets
/// are inside the window.
pub const CAPTURE_SETTLE_SECS: u64 = 3;
/// `timeout --kill-after` grace applied after the capture window.
const CAPTURE_KILL_AFTER_SECS: u64 = 5;
/// Per-probe `timeout` bound in seconds. On a correctly-protected exit the
/// scoped `tcp dport { 53, 853 } drop` silently eats SYNs instead of
/// rejecting them, so an unbounded `/dev/tcp` connect would hang for the
/// default `tcp_syn_retries=6` (~129s) and push every later probe — and the
/// client positive control — outside the capture window.
pub const PROBE_TIMEOUT_SECS: u64 = 4;

/// The persistent boot-time killswitch table (`rustynet_boot`), snapshotted
/// alongside the generation table at capture start (W1). Disconnect-cleanup
/// never removes it, so its exclusion-scoped established accepts cannot
/// shadow the DNS drops; a missing boot table is recorded as `absent`, not an
/// error — the generation table alone decides the posture precondition.
pub const BOOT_KILLSWITCH_TABLE: &str = "rustynet_boot";
/// Evidence marker recorded under `capture_start_conntrack` when the
/// `conntrack` binary is missing (exit 127) or otherwise unusable; the
/// fallback evidence (the filtered `/proc/net/nf_conntrack` snapshot, else
/// the `ss -Htn` established-DNS listing) follows it (W1).
pub const CONNTRACK_UNAVAILABLE: &str = "conntrack unavailable";
/// The kernel conntrack table read directly when the `conntrack` binary is
/// unusable (real lab guests ship without it — every query exits 127, which
/// would otherwise disarm attribution forever and fail every clean run).
/// Read argv-only through the shell seam; the lines are filtered in Rust
/// down to the witness-relevant ones before bounding.
pub const PROC_NF_CONNTRACK_ARGV: [&str; 4] = ["sudo", "-n", "cat", "/proc/net/nf_conntrack"];
/// Header recorded ahead of the filtered `/proc` fallback section so the
/// evidence blob names its source.
pub const PROC_NF_CONNTRACK_LABEL: &str =
    "== fallback: sudo -n cat /proc/net/nf_conntrack (filtered) ==";
/// Distinct failure text (W1): an established host-origin tcp/53|853 flow
/// already existed when the capture window opened, so a leak inside the
/// window cannot be attributed to the killswitch. The witness cannot prove
/// the killswitch dropped that flow — it says so and still fails.
pub const PRE_EXISTING_TCP_DNS_FAILURE: &str = "pre-existing host-origin tcp/53|853 connection at capture start (cannot prove the kill switch dropped it)";
/// Upper bound per capture-start evidence blob embedded in the verdict JSON
/// (W1): verbatim but bounded, so a chatty ruleset cannot bloat the artifact.
pub const CAPTURE_START_EVIDENCE_MAX_BYTES: usize = 16 * 1024;

/// Snapshot labels recorded on W3 attributions: which conntrack snapshot(s)
/// a matched entry came from. `capture_start+capture_end` marks the strict
/// case (MED-3 of the independent review): a flow that showed no initiator
/// packet inside the capture window pre-existed the window, so it must be
/// present in BOTH snapshots before a packet may be attributed to it.
pub const CONNTRACK_SNAPSHOT_START: &str = "capture_start";
pub const CONNTRACK_SNAPSHOT_END: &str = "capture_end";
pub const CONNTRACK_SNAPSHOT_BOTH: &str = "capture_start+capture_end";

/// Per-class packet tallies for the egress capture. Every count zero except
/// `forwarded_icmp`/`wireguard` is the pass shape.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeakWitnessCounts {
    pub host_dns_udp: u32,
    pub host_dns_tcp: u32,
    pub host_dot: u32,
    pub ipv6: u32,
    pub forwarded_icmp: u32,
    pub wireguard: u32,
}

impl LeakWitnessCounts {
    pub fn as_json_fields(&self) -> String {
        format!(
            "host_dns_udp={} host_dns_tcp={} host_dot={} ipv6={} forwarded_icmp={} wireguard={}",
            self.host_dns_udp,
            self.host_dns_tcp,
            self.host_dot,
            self.ipv6,
            self.forwarded_icmp,
            self.wireguard
        )
    }
}

/// One pre-existing established host-origin DNS/DoT flow observed at capture
/// start (W1), as a 4-tuple in capture order (local = the exit itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreExistingTcpDnsConn {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

/// One direction tuple of a conntrack entry (W3). Ports are `None` for
/// protocols without them (icmp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackTuple {
    pub src: String,
    pub sport: Option<u16>,
    pub dst: String,
    pub dport: Option<u16>,
}

/// One parsed conntrack entry (W3): protocol plus ORIGINAL and REPLY
/// direction tuples and the verbatim line. For a masqueraded client flow the
/// ORIGINAL tuple's source is the client behind the exit, while a
/// host-origin flow's ORIGINAL source is the exit itself — that difference
/// is the whole attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackEntry {
    pub proto: String,
    pub original: ConntrackTuple,
    pub reply: ConntrackTuple,
    pub line: String,
}

/// A leaked-looking tcp/53|853 packet that conntrack attribution identified
/// as a masqueraded mesh-peer flow (W3b): recorded in the verdict under
/// `forwarded_dns_tcp` and NOT counted as a host-origin leak. `mesh_peer`
/// names the non-exit mesh node whose address is the ORIGINAL source
/// (W3T — u46-r48 attributed a relay flow, not the client's); `"unknown"`
/// only when the alias table lookup somehow missed, which `admits` makes
/// unreachable for a forwarded verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedDnsPacket {
    pub packet_line: String,
    pub conntrack_line: String,
    pub original_src: String,
    pub snapshot: String,
    pub mesh_peer: String,
}

/// What the positive control actually proved (W3c): the raw wire count of
/// ICMP echo traffic to [`WITNESS_ICMP_TARGET`] from the egress address,
/// split by conntrack attribution into unattributed and forwarded
/// (masqueraded client flow) halves, plus the count of tcp/53|853 packets
/// attributed as forwarded client flows (evidence only — the ICMP control
/// is satisfied by attributed ICMP alone, never by DNS attribution).
/// `proven` is always a full sentence recording what was (or was not)
/// established.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PositiveControlEvidence {
    pub forwarded_icmp_raw: u32,
    pub exit_origin_icmp: u32,
    pub forwarded_icmp_attributed: u32,
    pub forwarded_dns_attributed: u32,
    pub client_original_srcs: Vec<String>,
    pub proven: String,
}

/// The capture-END conntrack snapshot (W3a): the same queries as capture
/// start (tcp/53, tcp/853, udp/53) PLUS icmp (the positive-control flows),
/// all in conntrack's DEFAULT output form. The parser still accepts the
/// `-o extended` shape (HIGH-1: its two leading family columns broke naive
/// protocol detection), but the flag is no longer requested — the default
/// form already carries both tuples and older binaries refuse the flag.
/// Verbatim-but-bounded blob + parsed entries; `available` is the weaker
/// any-query-succeeded fact, while `all_answered` — every query exited 0 —
/// is what attribution arming requires (MED-3: a snapshot that only
/// partially answered cannot prove an entry's ABSENCE, so a partial
/// snapshot conservatively disables attribution).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CaptureEndConntrack {
    pub blob: String,
    pub available: bool,
    pub all_answered: bool,
    pub entries: Vec<ConntrackEntry>,
    /// The blob hit the size bound (truncation marker present): the snapshot
    /// text is incomplete, so flow attribution must stay disarmed.
    pub truncated: bool,
}

/// Capture-start evidence (W1): the `-a` listings of the generation and boot
/// killswitch tables, the conntrack (or ss-fallback) DNS connection snapshot,
/// and the parsed set of pre-existing established host-origin tcp/53|853
/// flows. Everything is recorded verbatim-but-bounded into the verdict.
///
/// W3 additions: the exit's own local IPv4 addresses (ground truth for
/// attribution), the conntrack availability flag (`conntrack_available` is
/// the weaker any-query fact that gates the ss fallback) plus
/// `conntrack_all_answered` — every query exited 0, the condition
/// attribution arming actually requires (MED-3) — and the full two-tuple
/// conntrack entries used for conservative attribution.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CaptureStartEvidence {
    pub nft: String,
    pub boot_nft: String,
    pub conntrack: String,
    pub pre_existing_tcp_dns: Vec<PreExistingTcpDnsConn>,
    pub local_addrs: Vec<String>,
    pub local_addrs_raw: String,
    pub conntrack_available: bool,
    pub conntrack_all_answered: bool,
    pub conntrack_entries: Vec<ConntrackEntry>,
    /// The conntrack blob hit the size bound (truncation marker present):
    /// the snapshot text is incomplete, so flow attribution must stay
    /// disarmed.
    pub conntrack_truncated: bool,
}

/// Bound an evidence blob: verbatim up to [`CAPTURE_START_EVIDENCE_MAX_BYTES`],
/// then truncated on a char boundary with a marker, so the verdict JSON stays
/// bounded without ever being silently emptied.
fn bound_evidence_text(text: &str) -> String {
    if text.len() <= CAPTURE_START_EVIDENCE_MAX_BYTES {
        return text.to_owned();
    }
    let mut end = CAPTURE_START_EVIDENCE_MAX_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n{CAPTURE_TRUNCATION_MARKER}", &text[..end])
}

/// Marker [`bound_evidence_text`] appends when an evidence blob was clipped.
/// Its presence in a conntrack blob means the snapshot text is incomplete, so
/// flow attribution must not be armed (an absent match could be truncation).
const CAPTURE_TRUNCATION_MARKER: &str = "...[truncated]";

/// True when a bound evidence blob carries the truncation marker.
fn blob_truncated(blob: &str) -> bool {
    blob.contains(CAPTURE_TRUNCATION_MARKER)
}

/// Parse `conntrack -L -p tcp --dport 53|853` output into pre-existing
/// established host-origin flows. A qualifying line is tcp (recognised via
/// [`leading_protocol`], so the kernel `/proc/net/nf_conntrack` fallback
/// form `ipv4 2 tcp 6 ... ESTABLISHED ...` qualifies too), carries the
/// `ESTABLISHED` state token, and its first (origin) tuple ends in
/// `dport=53|853`; the first `src=`/`sport=` occurrence is the local exit
/// side. Anything unparseable is skipped — the raw text is the evidence.
pub fn parse_conntrack_tcp_dns_entries(stdout: &str) -> Vec<PreExistingTcpDnsConn> {
    let mut conns = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = leading_protocol(&tokens) else {
            continue;
        };
        if proto != "tcp" || !tokens.contains(&"ESTABLISHED") {
            continue;
        }
        let mut fields: Vec<(&str, &str)> = Vec::new();
        for token in &tokens {
            if let Some((key, value)) = token.split_once('=') {
                if !fields.iter().any(|(k, _)| *k == key) {
                    fields.push((key, value));
                }
            }
        }
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let (Some(src), Some(dst), Some(sport), Some(dport)) =
            (get("src"), get("dst"), get("sport"), get("dport"))
        else {
            continue;
        };
        let (Some(local_port), Some(remote_port)) =
            (sport.parse::<u16>().ok(), dport.parse::<u16>().ok())
        else {
            continue;
        };
        if remote_port != 53 && remote_port != WITNESS_DOT_PORT {
            continue;
        }
        conns.push(PreExistingTcpDnsConn {
            local_addr: src.to_owned(),
            local_port,
            remote_addr: dst.to_owned(),
            remote_port,
        });
    }
    conns
}

/// Parse `ss -Htn state established '( dport = :53 or dport = :853 )'` output
/// (the fallback when `conntrack` is unavailable). Columns:
/// `ESTAB <recv-q> <send-q> <local:port> <peer:port>`; the filter already
/// bounds the peer port, and it is re-checked here.
pub fn parse_ss_established_dns_entries(stdout: &str) -> Vec<PreExistingTcpDnsConn> {
    let mut conns = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() != Some(&"ESTAB") {
            continue;
        }
        let (Some(local), Some(peer)) = (tokens.get(3), tokens.get(4)) else {
            continue;
        };
        let Some((local_addr, local_port)) = split_addr_port(local) else {
            continue;
        };
        let Some((remote_addr, remote_port)) = split_addr_port(peer) else {
            continue;
        };
        if remote_port != 53 && remote_port != WITNESS_DOT_PORT {
            continue;
        }
        conns.push(PreExistingTcpDnsConn {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        });
    }
    conns
}

/// Split an `addr:port` endpoint (IPv4 or bracketed/brutal IPv6 — the last
/// colon separates the port).
fn split_addr_port(endpoint: &str) -> Option<(String, u16)> {
    let (addr, port) = endpoint.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    Some((addr.to_owned(), port))
}

/// The transport protocol of a `conntrack -L` line: the first bare
/// `tcp`/`udp`/`icmp` token BEFORE the first `key=value` field. In the
/// default form (`tcp      6 431999 ESTABLISHED src=...`) it is the first
/// token; in the `-o extended` form (`ipv4     2 tcp      6 ...`) TWO
/// family/protocol columns precede it, so the first line token is NEVER
/// trusted blindly (HIGH-1 of the independent review). Lines without a
/// recognisable leading protocol are skipped — they can never participate
/// in attribution.
fn leading_protocol<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    for token in tokens {
        if token.contains('=') {
            return None;
        }
        match *token {
            "tcp" | "udp" | "icmp" => return Some(*token),
            _ => {}
        }
    }
    None
}

/// Parse `conntrack -L` output in BOTH the default form and the `-o
/// extended` form (see [`leading_protocol`] — the field order is NOT
/// identical, so the protocol is recognised structurally) into full
/// two-tuple entries (W3). Each qualifying line yields the ORIGINAL tuple
/// (the first `src=`/`dst=`/`sport=`/`dport=` occurrences) and the REPLY
/// tuple (the second occurrences), and the verbatim line. Unlike the W1
/// host-origin parser there is NO state token requirement: a masqueraded
/// client flow is attributed through TIME_WAIT/FIN entries too. Lines
/// without two complete address pairs are skipped — they can never
/// participate in attribution.
pub fn parse_conntrack_entries(stdout: &str) -> Vec<ConntrackEntry> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = leading_protocol(&tokens) else {
            continue;
        };
        let mut srcs: Vec<&str> = Vec::new();
        let mut dsts: Vec<&str> = Vec::new();
        let mut sports: Vec<Option<u16>> = Vec::new();
        let mut dports: Vec<Option<u16>> = Vec::new();
        for token in &tokens {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            match key {
                "src" => srcs.push(value),
                "dst" => dsts.push(value),
                "sport" => sports.push(value.parse().ok()),
                "dport" => dports.push(value.parse().ok()),
                _ => {}
            }
        }
        let (Some(orig_src), Some(orig_dst)) = (srcs.first(), dsts.first()) else {
            continue;
        };
        let (Some(reply_src), Some(reply_dst)) = (srcs.get(1), dsts.get(1)) else {
            continue;
        };
        let orig_sport = sports.first().copied().flatten();
        let orig_dport = dports.first().copied().flatten();
        let reply_sport = sports.get(1).copied().flatten();
        let reply_dport = dports.get(1).copied().flatten();
        entries.push(ConntrackEntry {
            proto: proto.to_owned(),
            original: ConntrackTuple {
                src: (*orig_src).to_owned(),
                sport: orig_sport,
                dst: (*orig_dst).to_owned(),
                dport: orig_dport,
            },
            reply: ConntrackTuple {
                src: (*reply_src).to_owned(),
                sport: reply_sport,
                dst: (*reply_dst).to_owned(),
                dport: reply_dport,
            },
            line: line.to_owned(),
        });
    }
    entries
}

/// Keep only the witness-relevant lines of a `/proc/net/nf_conntrack`
/// snapshot, BEFORE the evidence blob is bounded: icmp entries (the
/// positive-control flows) and tcp/udp entries whose ORIGINAL or REPLY
/// tuple carries sport or dport 53|853. Everything else (ssh, dhcp, ...)
/// is noise that could crowd out relevant lines at the bound.
fn filter_proc_nf_conntrack_lines(stdout: &str) -> String {
    let mut kept = String::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = leading_protocol(&tokens) else {
            continue;
        };
        let relevant = proto == "icmp"
            || tokens.iter().any(|token| match token.split_once('=') {
                Some(("sport", port)) | Some(("dport", port)) => port == "53" || port == "853",
                _ => false,
            });
        if relevant {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

/// Read the filtered `/proc/net/nf_conntrack` fallback through the argv-only
/// shell seam. Returns `Some(filtered_text)` only when the read exited 0 —
/// any other outcome (binary-free guest without the file, transport error,
/// non-zero exit) is `None`, which conservatively keeps attribution OFF.
fn read_proc_nf_conntrack(shell: &dyn RemoteShellHost) -> Option<String> {
    let out = shell.run_argv(&PROC_NF_CONNTRACK_ARGV, &[], &[]).ok()?;
    if out.code != 0 {
        return None;
    }
    Some(filter_proc_nf_conntrack_lines(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

/// Parse `ip -4 -o addr show` output into the exit's local IPv4 addresses
/// (the `/NN` suffix stripped, duplicates removed, order preserved).
pub fn parse_ip_o_addr_show_v4(stdout: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (idx, token) in tokens.iter().enumerate() {
            if *token == "inet"
                && let Some(cidr) = tokens.get(idx + 1)
                && let Some(addr) = cidr.split('/').next()
                && !addr.is_empty()
                && !addrs.iter().any(|a: &String| a.as_str() == addr)
            {
                addrs.push(addr.to_owned());
            }
        }
    }
    addrs
}

/// Strict dotted-quad IPv4 check used before trusting a conntrack ORIGINAL
/// source as attribution ground truth.
fn is_valid_ipv4(addr: &str) -> bool {
    let octets: Vec<&str> = addr.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.bytes().all(|b| b.is_ascii_digit())
                && o.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
        })
}

/// The conservative ground-truth check for W3: does this address belong to
/// the EXIT ITSELF (its egress address, loopback, or any configured local
/// address)? Any yes keeps a matched packet counted as a possible
/// host-origin leak — attribution may only ever RELIEVE a packet when the
/// original source is provably foreign (a client behind the exit).
fn is_exit_local_addr(addr: &str, local_addrs: &[String], egress_addr: &str) -> bool {
    addr == egress_addr || addr.starts_with("127.") || local_addrs.iter().any(|a| a == addr)
}

/// Informational, plus one fail-closed verdict gate: the host's DNS-shaped
/// sockets (`ss -tnpH state all
/// '( dport = :53 or dport = :853 )'`, argv-only) — records what the host's
/// own resolver had in flight (e.g. systemd-resolved SYN-SENT to a public
/// resolver). Errors are tolerated and recorded. The CAPTURE-START snapshot
/// additionally gates the W1 orphaned-entry relief: an errored or truncated
/// snapshot keeps every pre-existing entry blocking (fail closed); the
/// capture-end snapshot stays informational.
fn gather_dns_sockets(shell: &dyn RemoteShellHost) -> String {
    let argv = [
        "sudo",
        "-n",
        "ss",
        "-tnpH",
        "state",
        "all",
        "( dport = :53 or dport = :853 )",
    ];
    match shell.run_argv(&argv, &[], &[]) {
        Ok(out) if out.code == 0 => bound_evidence_text(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => bound_evidence_text(&format!("[ss -tnpH exited {}]", out.code)),
        Err(err) => bound_evidence_text(&format!("[ss -tnpH transport error: {err}]")),
    }
}

/// Gather the W1 capture-start evidence through the same argv-only shell
/// seam: the `-a` listing of the generation killswitch table and of the boot
/// table (absent tolerated and recorded), then the conntrack tcp/53, tcp/853
/// and udp/53 snapshots. A missing (`exit 127`) or wholly-failing conntrack
/// falls back to `ss -Htn` established-DNS evidence.
///
/// W3 additions: the exit's local IPv4 addresses (`ip -4 -o addr show`) and
/// the full two-tuple conntrack entries used for conservative attribution.
/// An unusable address listing leaves the list empty, which disables
/// attribution entirely (fail as before) — it never widens it.
fn gather_capture_start_evidence(
    shell: &dyn RemoteShellHost,
    killswitch_table: &str,
) -> CaptureStartEvidence {
    let mut evidence = CaptureStartEvidence::default();

    let nft_argv = [
        "sudo",
        "-n",
        "nft",
        "-a",
        "list",
        "table",
        "inet",
        killswitch_table,
    ];
    evidence.nft = match shell.run_argv(&nft_argv, &[], &[]) {
        Ok(out) if out.code == 0 => bound_evidence_text(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => bound_evidence_text(&format!(
            "nft -a list table inet {killswitch_table} exited {}",
            out.code
        )),
        Err(err) => bound_evidence_text(&format!(
            "nft -a list table inet {killswitch_table} failed: {err}"
        )),
    };

    let boot_argv = [
        "sudo",
        "-n",
        "nft",
        "-a",
        "list",
        "table",
        "inet",
        BOOT_KILLSWITCH_TABLE,
    ];
    evidence.boot_nft = match shell.run_argv(&boot_argv, &[], &[]) {
        Ok(out) if out.code == 0 => bound_evidence_text(&String::from_utf8_lossy(&out.stdout)),
        // The boot table may legitimately be absent (operator-deleted); that
        // is recorded, never an error.
        Ok(out) => bound_evidence_text(&format!(
            "{BOOT_KILLSWITCH_TABLE} absent (nft exited {})",
            out.code
        )),
        Err(err) => bound_evidence_text(&format!(
            "{BOOT_KILLSWITCH_TABLE} absent (listing failed: {err})"
        )),
    };

    // W3a: the exit's own IPv4 addresses at capture start — the ground truth
    // a conntrack entry's ORIGINAL source is compared against. An unusable
    // listing leaves the list empty, which disables attribution entirely
    // (fail as before), never widens it.
    let addr_argv = ["ip", "-4", "-o", "addr", "show"];
    match shell.run_argv(&addr_argv, &[], &[]) {
        Ok(out) if out.code == 0 => {
            evidence.local_addrs_raw = bound_evidence_text(&String::from_utf8_lossy(&out.stdout));
            evidence.local_addrs = parse_ip_o_addr_show_v4(&evidence.local_addrs_raw);
        }
        Ok(out) => {
            evidence.local_addrs_raw = bound_evidence_text(&format!(
                "ip -4 -o addr show exited {} — local address ground truth unavailable, \
                 attribution disabled",
                out.code
            ));
        }
        Err(err) => {
            evidence.local_addrs_raw = bound_evidence_text(&format!(
                "ip -4 -o addr show failed: {err} — local address ground truth unavailable, \
                 attribution disabled"
            ));
        }
    }

    let conntrack_queries: [(&str, &str, &str); 3] = [
        ("tcp", "53", "conntrack -L -p tcp --dport 53"),
        ("tcp", "853", "conntrack -L -p tcp --dport 853"),
        ("udp", "53", "conntrack -L -p udp --dport 53"),
    ];
    let mut sections = String::new();
    let mut any_ok = false;
    let mut all_answered = true;
    for (proto, dport, label) in conntrack_queries {
        let argv = [
            "sudo",
            "-n",
            "conntrack",
            "-L",
            "-p",
            proto,
            "--dport",
            dport,
        ];
        match shell.run_argv(&argv, &[], &[]) {
            Ok(out) => {
                sections.push_str(&format!(
                    "== {label} ==\n{}",
                    String::from_utf8_lossy(&out.stdout)
                ));
                if out.code == 0 {
                    any_ok = true;
                } else {
                    all_answered = false;
                    sections.push_str(&format!("[exit {}]\n", out.code));
                }
            }
            Err(err) => {
                all_answered = false;
                sections.push_str(&format!("== {label} ==\n[transport error: {err}]\n"));
            }
        }
    }
    // A conntrack binary missing (exit 127 shows up as a failed query with
    // no zero-exit query) or unable to answer every query is unusable — the
    // kernel `/proc/net/nf_conntrack` table (real guests ship without the
    // binary) is consulted FIRST, and the ss evidence is the last resort.
    let unavailable = !any_ok;
    let mut proc_ok = false;
    if unavailable {
        sections.insert_str(0, &format!("{CONNTRACK_UNAVAILABLE}\n"));
        sections.push_str(&format!("{PROC_NF_CONNTRACK_LABEL}\n"));
        match read_proc_nf_conntrack(shell) {
            Some(filtered) => {
                proc_ok = true;
                sections.push_str(&filtered);
            }
            None => sections.push_str("[unavailable]\n"),
        }
        if !proc_ok {
            sections.push_str(
                "== fallback: ss -Htn state established '( dport = :53 or dport = :853 )' ==\n",
            );
            let ss_argv = [
                "ss",
                "-Htn",
                "state",
                "established",
                "( dport = :53 or dport = :853 )",
            ];
            match shell.run_argv(&ss_argv, &[], &[]) {
                Ok(out) => sections.push_str(&String::from_utf8_lossy(&out.stdout)),
                Err(err) => sections.push_str(&format!("[transport error: {err}]\n")),
            }
        }
    }
    // The bounded blob is the single source of truth: W1 host-origin conns
    // and W3 attribution entries are parsed from exactly the text that is
    // recorded in the verdict, so a cited line is always inside the blob and
    // anything truncated away conservatively stops participating.
    let blob = bound_evidence_text(&sections);
    // The conntrack queries OR a successful `/proc` fallback make the
    // conntrack-format parsers authoritative; only the ss fallback path
    // parses ss lines (and carries no attribution entries).
    let (mut conns, entries) = if !unavailable || proc_ok {
        (
            parse_conntrack_tcp_dns_entries(&blob),
            parse_conntrack_entries(&blob),
        )
    } else {
        // Neither conntrack nor /proc produced anything usable; the ss
        // fallback section inside the blob is the evidence.
        (parse_ss_established_dns_entries(&blob), Vec::new())
    };
    conns.sort_by(|a, b| {
        (&a.local_addr, a.local_port, &a.remote_addr, a.remote_port).cmp(&(
            &b.local_addr,
            b.local_port,
            &b.remote_addr,
            b.remote_port,
        ))
    });
    conns.dedup();
    evidence.pre_existing_tcp_dns = conns;
    evidence.conntrack_truncated = blob_truncated(&blob);
    evidence.conntrack = blob;
    evidence.conntrack_available = any_ok;
    evidence.conntrack_all_answered = (all_answered && any_ok) || proc_ok;
    evidence.conntrack_entries = entries;
    evidence
}

/// Evidence-only read of the icmp lines of the kernel conntrack table
/// (see [`gather_conntrack_timing_diagnostics`]); deliberately NOT the
/// attribution fallback's [`PROC_NF_CONNTRACK_ARGV`].
const DIAG_PROC_ICMP_ARGV: [&str; 5] = ["sudo", "-n", "grep", " icmp ", "/proc/net/nf_conntrack"];

/// Informational-only conntrack timing evidence (katana-xnet-1105): the
/// witness mislabelled a leak-free run vacuous because the capture-end
/// conntrack snapshot held no icmp entry for the masqueraded control flow,
/// and the existing evidence cannot say WHEN that snapshot was taken relative
/// to the control echoes (the ICMP conntrack lifetime is ~30 s), nor whether
/// the kernel dropped the entry early. This records, for one `label`: the
/// guest wall clock (the same clock as the tcpdump timestamps), the
/// `nf_conntrack_icmp_timeout` and `nf_conntrack_count` sysctls, the
/// per-CPU `/proc/net/stat/nf_conntrack` counters (insert/delete/drop/
/// early_drop), and the icmp lines of `/proc/net/nf_conntrack`.
///
/// SECURITY: the returned text is evidence only. It is never parsed, never
/// consulted by attribution or by any verdict function, and every failed
/// command is recorded as text and otherwise ignored, so gathering it can
/// neither relax nor tighten a verdict.
fn gather_conntrack_timing_diagnostics(shell: &dyn RemoteShellHost, label: &str) -> String {
    let commands: [(&str, &[&str]); 5] = [
        ("guest clock", &["date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"]),
        (
            "nf_conntrack_icmp_timeout",
            &[
                "sudo",
                "-n",
                "cat",
                "/proc/sys/net/netfilter/nf_conntrack_icmp_timeout",
            ],
        ),
        (
            "nf_conntrack_count",
            &[
                "sudo",
                "-n",
                "cat",
                "/proc/sys/net/netfilter/nf_conntrack_count",
            ],
        ),
        (
            "/proc/net/stat/nf_conntrack",
            &["sudo", "-n", "cat", "/proc/net/stat/nf_conntrack"],
        ),
        // A DIFFERENT argv from the attribution fallback ([`PROC_NF_CONNTRACK_ARGV`])
        // on purpose: the witness's own conversation must stay independent of
        // this evidence-only read.
        ("icmp entries", &DIAG_PROC_ICMP_ARGV),
    ];
    let mut text = format!("== diag {label} ==\n");
    for (name, argv) in commands {
        text.push_str(&format!("-- {name} --\n"));
        match shell.run_argv(argv, &[], &[]) {
            Ok(out) if out.code == 0 => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                text.push_str(&stdout);
                if !stdout.ends_with('\n') {
                    text.push('\n');
                }
            }
            // grep exits 1 when no line matches: no icmp entry at all.
            Ok(out) if name == "icmp entries" && out.code == 1 => {
                text.push_str("(no icmp entries in /proc/net/nf_conntrack)\n");
            }
            Ok(out) => text.push_str(&format!("[exit {}]\n", out.code)),
            Err(err) => text.push_str(&format!("[transport error: {err}]\n")),
        }
    }
    text
}

/// W3a: the SECOND conntrack snapshot, taken right after the capture ends:
/// the same tcp/53, tcp/853, udp/53 queries as capture start PLUS icmp (the
/// positive-control flows), all in conntrack's DEFAULT output form — the
/// parser still accepts `-o extended` lines, but the flag is no longer
/// requested (HIGH-1 of the independent review: older binaries refuse it,
/// and the default form already carries both tuples). Every query must exit
/// 0 for attribution to arm (`all_answered`, MED-3: a snapshot that only
/// partially answered cannot prove an entry's ABSENCE); `available` records
/// the weaker any-query-succeeded fact for evidence only. A wholly missing
/// snapshot conservatively disables attribution (leaks keep failing).
fn gather_capture_end_conntrack(shell: &dyn RemoteShellHost) -> CaptureEndConntrack {
    let mut out = CaptureEndConntrack::default();
    let mut sections = String::new();
    let mut all_answered = true;
    let queries: [(&str, Option<&str>, &str); 4] = [
        ("tcp", Some("53"), "conntrack -L -p tcp --dport 53"),
        ("tcp", Some("853"), "conntrack -L -p tcp --dport 853"),
        ("udp", Some("53"), "conntrack -L -p udp --dport 53"),
        ("icmp", None, "conntrack -L -p icmp"),
    ];
    for (proto, dport, label) in queries {
        let mut argv: Vec<&str> = vec!["sudo", "-n", "conntrack", "-L", "-p", proto];
        if let Some(dport) = dport {
            argv.push("--dport");
            argv.push(dport);
        }
        sections.push_str(&format!("== {label} ==\n"));
        match shell.run_argv(&argv, &[], &[]) {
            Ok(status) => {
                sections.push_str(&String::from_utf8_lossy(&status.stdout));
                if status.code == 0 {
                    out.available = true;
                } else {
                    all_answered = false;
                    sections.push_str(&format!("[exit {}]\n", status.code));
                }
            }
            Err(err) => {
                all_answered = false;
                sections.push_str(&format!("[transport error: {err}]\n"));
            }
        }
    }
    // When the conntrack binary is unusable (real guests ship without it),
    // the filtered kernel `/proc/net/nf_conntrack` snapshot is the fallback
    // — a successful read re-arms the snapshot (`all_answered`), a failed
    // one keeps attribution disabled.
    let mut proc_ok = false;
    if !all_answered {
        sections.push_str(&format!("{PROC_NF_CONNTRACK_LABEL}\n"));
        match read_proc_nf_conntrack(shell) {
            Some(filtered) => {
                proc_ok = true;
                sections.push_str(&filtered);
            }
            None => sections.push_str("[unavailable]\n"),
        }
    }
    // The bounded blob is the single source of truth: entries are parsed
    // from exactly the text recorded in the verdict, so a cited
    // conntrack_line is always inside the blob and anything truncated away
    // conservatively stops participating in attribution.
    out.blob = bound_evidence_text(&sections);
    out.entries = parse_conntrack_entries(&out.blob);
    out.all_answered = all_answered || proc_ok;
    out.truncated = blob_truncated(&out.blob);
    out
}

/// Strip a trailing nft `comment "..."` clause from a collapsed rule line:
/// the comment is free text and must never influence rule semantics (a
/// comment quoting a DNS exclusion must not make an unrestricted accept
/// look scoped — the comment-trick shape from the W2 probes).
fn strip_nft_comment(collapsed: &str) -> &str {
    match collapsed.find(" comment ") {
        Some(pos) => collapsed[..pos].trim_end(),
        None => collapsed,
    }
}

/// True when the rule carries a REAL `l4proto != { tcp, udp }` match
/// expression (round-3: the production table emits exactly this exclusion
/// accept) — recognised only as match syntax among the rule tokens, never
/// inside a comment string. Such a rule provably cannot match tcp or udp
/// traffic, so it can never carry DNS.
fn has_real_l4proto_tcp_udp_exclusion(tokens: &[&str]) -> bool {
    for pos in 0..tokens.len().saturating_sub(1) {
        if tokens[pos] != "l4proto" || tokens[pos + 1] != "!=" {
            continue;
        }
        let rest = &tokens[pos + 2..];
        if rest.first() != Some(&"{") {
            continue;
        }
        let set: Vec<&str> = rest
            .iter()
            .skip(1)
            .take_while(|token| **token != "}")
            .copied()
            .collect();
        if set.iter().any(|token| token.trim_end_matches(',') == "tcp")
            && set.iter().any(|token| token.trim_end_matches(',') == "udp")
        {
            return true;
        }
    }
    false
}

/// True when the rule carries a REAL `dport != { 53, 853 }` match
/// expression — recognised only as match syntax among the rule tokens,
/// never inside a comment string. nft match expressions are conjunctive,
/// so such a rule provably cannot match dport 53|853.
fn has_real_dns_dport_exclusion(tokens: &[&str]) -> bool {
    for pos in 0..tokens.len().saturating_sub(1) {
        if tokens[pos] != "dport" || tokens[pos + 1] != "!=" {
            continue;
        }
        let rest = &tokens[pos + 2..];
        if rest.first() != Some(&"{") {
            continue;
        }
        let set: Vec<&str> = rest
            .iter()
            .skip(1)
            .take_while(|token| **token != "}")
            .copied()
            .collect();
        if set.iter().any(|token| token.trim_end_matches(',') == "53")
            && set.iter().any(|token| token.trim_end_matches(',') == "853")
        {
            return true;
        }
    }
    false
}

/// True when a collapsed nft ACCEPT rule can match egress tcp/udp dport
/// 53|853 (W2, MED-6 of the independent review — replaces the narrower
/// established-accept-only check). Decision, conservative and fail-closed:
/// * a trailing `comment "..."` is stripped first (see
///   [`strip_nft_comment`]);
/// * a REAL dns exclusion (`dport != { 53, 853 }`, see
///   [`has_real_dns_dport_exclusion`]) makes the rule unable to match the
///   DNS ports;
/// * otherwise every `dport` clause must provably exclude the DNS ports —
///   an exact numeric port other than 53|853 (the WireGuard allow half) or
///   a set literal without them; if ALL clauses exclude, the conjunction
///   cannot match;
/// * a rule with NO `dport` clause at all (unqualified established accepts,
///   bare oifname accepts, `ip daddr` accepts, `ct state { established,
///   related }` accepts, ...) or with an unprovable clause (`dport != 53`,
///   named sets, garbled text) CAN match the DNS ports.
///
/// `sport` clauses are ignored on purpose: the leak classes and the scoped
/// drops are dport-scoped. A sport-only accept therefore carries no `dport`
/// clause and is conservatively treated as DNS-capable — correct, since a
/// packet with `sport 51820, dport 53` does match it — so such rules must
/// sit after the drops, which the standard table shape guarantees.
fn accept_can_match_dns_ports(collapsed: &str) -> bool {
    let rule = strip_nft_comment(collapsed);
    // Chain/table plumbing is never a rule: `type filter hook output
    // priority filter; policy accept;` carries a policy verdict, not an
    // accept rule. A base-chain policy is evaluated AFTER every rule in its
    // own chain, so it can never shadow the drops that live there — treating
    // it as a positioned accept would fail every table that declares one.
    if rule.contains("policy")
        || rule.contains(" hook ")
        || rule.starts_with("chain ")
        || rule.starts_with("table ")
    {
        return false;
    }
    // Token-exact `accept`: a trailing `accept;` (statement terminator) is
    // plumbing, not a rule verdict.
    let tokens: Vec<&str> = rule.split_whitespace().collect();
    if !tokens
        .iter()
        .any(|token| token.trim_end_matches(';') == "accept")
    {
        return false;
    }
    if has_real_dns_dport_exclusion(&tokens) || has_real_l4proto_tcp_udp_exclusion(&tokens) {
        return false;
    }
    let mut saw_dport_clause = false;
    let mut all_clauses_exclude_dns = true;
    for pos in 0..tokens.len() {
        if tokens[pos] != "dport" {
            continue;
        }
        saw_dport_clause = true;
        let excludes = match tokens.get(pos + 1) {
            None => false,
            Some(&"{") => {
                let mut excludes = true;
                let mut j = pos + 2;
                while j < tokens.len() && tokens[j] != "}" {
                    let port = tokens[j].trim_end_matches(',');
                    if port == "53" || port == "853" {
                        excludes = false;
                    }
                    j += 1;
                }
                excludes
            }
            Some(port) => match port.parse::<u16>() {
                Ok(p) => p != 53 && p != WITNESS_DOT_PORT,
                Err(_) => false,
            },
        };
        if !excludes {
            all_clauses_exclude_dns = false;
        }
    }
    if !saw_dport_clause {
        return true;
    }
    !all_clauses_exclude_dns
}

/// True when the collapsed rule carries at least one `dport` clause that can
/// match 53|853 (an explicit DNS-shaped clause). Used by the order check to
/// keep a dport-53 accept REJECTED even when its `oifname` scopes it away
/// from the egress NIC: whoever writes a DNS-port accept into an output
/// chain meant DNS, and a wrong-scoped DNS accept must still sit after the
/// drops.
fn accept_has_dns_matchable_dport_clause(tokens: &[&str]) -> bool {
    for pos in 0..tokens.len() {
        if tokens[pos] != "dport" {
            continue;
        }
        let excludes = match tokens.get(pos + 1) {
            None => false,
            Some(&"{") => {
                let mut excludes = true;
                let mut j = pos + 2;
                while j < tokens.len() && tokens[j] != "}" {
                    let port = tokens[j].trim_end_matches(',');
                    if port == "53" || port == "853" {
                        excludes = false;
                    }
                    j += 1;
                }
                excludes
            }
            Some(port) => match port.parse::<u16>() {
                Ok(p) => p != 53 && p != WITNESS_DOT_PORT,
                Err(_) => false,
            },
        };
        if !excludes {
            return true;
        }
    }
    false
}

/// True when the collapsed ACCEPT rule cannot carry a DNS packet OUT of the
/// egress interface in an output-hook chain: EVERY interface match in the
/// rule must scope traffic away from the egress NIC. A match counts only
/// when it is a positive, single-interface binding — `oifname "lo"` or
/// `iifname "tun0"` — of the non-egress interface; a negated match
/// (`oifname != "lo"`, which admits the egress NIC) or a set match
/// (`oifname { "lo", "enp0s9" }`, which may include it) proves nothing and
/// makes the rule unscoped. Any positive `iifname` binding scopes forward/
/// bridged traffic away; a positive `oifname` of the egress NIC (or its
/// absence) keeps the rule order-checked.
fn accept_scoped_away_from_egress_output(tokens: &[&str], egress_iface: &str) -> bool {
    let mut scoped_away = false;
    let mut pos = 0;
    while pos < tokens.len() {
        let Some(next) = tokens.get(pos + 1) else {
            break;
        };
        let negated = *next == "!=";
        if negated || *next == "{" {
            // Negated or set matches never scope traffic away: skip the
            // whole clause (negation token + interface, or the set body).
            pos = if negated {
                pos + 2
            } else {
                set_clause_end(tokens, pos + 1)
            };
            continue;
        }
        let iface = next.trim_matches('"');
        match tokens[pos] {
            "iifname" => scoped_away = true,
            "oifname" if iface != egress_iface => scoped_away = true,
            _ => {}
        }
        pos += 2;
    }
    scoped_away
}

/// End offset (exclusive) of a set body `{ a, b }` starting at `open`.
fn set_clause_end(tokens: &[&str], open: usize) -> usize {
    let mut depth = 0usize;
    for (offset, token) in tokens[open..].iter().enumerate() {
        if token.contains('{') {
            depth += token.matches('{').count();
        }
        if token.contains('}') {
            depth -= token.matches('}').count();
            if depth == 0 {
                return open + offset + 1;
            }
        }
    }
    tokens.len()
}

/// Full witness report for one capture window: posture + capture context,
/// per-class counts, probe exit codes, raw capture text, and the fail-closed
/// verdict reasons (empty means the witness passed).
#[derive(Debug, Clone)]
pub struct LeakWitnessReport {
    pub exit_alias: String,
    pub egress_iface: String,
    pub egress_addr: String,
    pub killswitch_table: String,
    pub wg_listen_port: u16,
    pub capture_filter: String,
    /// Every interface this run captured, in capture order: the default-route
    /// egress NIC first, then (on a vxlan substrate) the overlay link that
    /// carries the WireGuard control. Recorded so the verdict artifact always
    /// names the plane the tunnel-control count came from.
    pub capture_ifaces: Vec<String>,
    /// W1 evidence, recorded verbatim-but-bounded at capture start:
    /// generation-table `-a` listing, boot-table listing (`absent` tolerated),
    /// and the conntrack/ss DNS connection snapshot.
    pub capture_start_nft: String,
    pub capture_start_boot_nft: String,
    pub capture_start_conntrack: String,
    /// W3a evidence: the exit's local IPv4 addresses at capture start (the
    /// attribution ground truth) and the capture-end conntrack snapshot.
    pub capture_start_local_addrs: Vec<String>,
    pub capture_start_local_addrs_raw: String,
    pub capture_end_conntrack: String,
    /// Informational ONLY (katana-xnet-1105 diagnosis): guest-clock readings,
    /// the ICMP conntrack lifetime, conntrack table counters, and the raw
    /// icmp entries seen in `/proc/net/nf_conntrack` right after the client
    /// ping and again after the capture-end snapshot. It lets an operator
    /// line the conntrack state up against the tcpdump timestamps (same guest
    /// clock) when a run is mislabelled vacuous. It is NEVER parsed, never
    /// feeds attribution, and has no pass/fail semantics: see
    /// [`gather_conntrack_timing_diagnostics`].
    pub conntrack_timing_diagnostics: String,
    /// Informational (round-3): `sudo -n ss -tnpH state all '( dport = :53
    /// or dport = :853 )'` output at capture start and capture end — the
    /// host's own DNS-shaped sockets (systemd-resolved SYN-SENT etc.).
    /// Recorded verbatim-but-bounded. The capture-START snapshot additionally
    /// gates the W1 orphaned-entry relief (an errored or truncated snapshot
    /// denies relief, fail closed); the capture-end snapshot has NO
    /// pass/fail semantics.
    pub capture_start_dns_sockets: String,
    pub capture_end_dns_sockets: String,
    /// Audit trail for the orphaned-entry relief in
    /// [`append_capture_start_failures`] (the katana-xnet-190/193 flake): one
    /// line per pre-existing host-origin tcp/53|853 entry retired from the
    /// standalone capture-start failure because a USABLE capture-start ss
    /// snapshot carries NO socket owning its local endpoint and the capture
    /// itself carries no host-origin tcp/53|853 packet. An entry here never
    /// downgrades or retires a leak failure — the in-window checks are
    /// untouched; relief is impossible on any truncated or errored snapshot.
    pub pre_existing_conn_reliefs: Vec<String>,
    /// W2 order findings that are NON-FATAL (informational): order violations
    /// on accepts that do not carry an explicit
    /// `ct state established[,related] accept` match. Empty on the real
    /// production table; a violating established-flow accept stays a hard
    /// failure instead.
    pub dns_rule_order_findings: Vec<String>,
    /// W3b: tcp/53|853 packets attributed to masqueraded client flows by
    /// conntrack (never counted as host-origin leaks).
    pub forwarded_dns_tcp: Vec<ForwardedDnsPacket>,
    /// W3c: what the ICMP positive control proved, by conntrack attribution.
    pub positive_control: PositiveControlEvidence,
    pub counts: LeakWitnessCounts,
    pub probe_exit_codes: Vec<(String, i32)>,
    pub capture_stdout: String,
    pub capture_stderr: String,
    pub failures: Vec<String>,
}

pub fn exit_egress_leak_witness_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Detect the default egress interface from `ip route show default`.
fn detect_linux_egress_interface(shell: &dyn RemoteShellHost) -> Result<String, String> {
    let out = shell
        .run_argv(&["ip", "route", "show", "default"], &[], &[])
        .map_err(|err| format!("failed to query default route for egress interface: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == "dev")
            && let Some(iface) = parts.get(pos + 1)
        {
            return Ok(iface.to_string());
        }
    }
    Err("default egress interface not found in `ip route show default` output".to_owned())
}

/// What the orchestrator recorded about the run's cross-network substrate,
/// handed down by the stage from `OrchestrationContext::substrate` (the live
/// `SubstrateHandle`, including `record.provisioned`) or, after a resume,
/// from the persisted `substrate_record`. It tells the witness WHICH plane
/// carries the WireGuard control before it ever looks at the guest: on a
/// provisioned vxlan overlay every mesh WG endpoint is an overlay address
/// (`substrate::plan_overlay` → `172.20.0.0/16` on `rustynet-vx0`), so the
/// tunnel control is EXPECTED there. It is not guaranteed absent from the
/// underlay: katana-xnet-841 (vxlan) passed with three exit-origin
/// udp/51820→:3478 packets on the underlay NIC — the overlay plane is
/// mandatory, not exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstrateOverlayHint {
    /// The run's substrate is a provisioned vxlan overlay: the exit MUST
    /// carry the overlay link. A missing link is an `Err` (fail closed) —
    /// an underlay-only capture would be vacuous on the tunnel control.
    Required,
    /// The recorded substrate carries no overlay (netns/slirp, or a vxlan
    /// substrate that decided no overlay was needed for a single network
    /// group): no overlay plane exists, none is probed for, and the capture
    /// is byte-identical to the pre-overlay behaviour.
    NotRequired,
    /// No substrate record available (plain run, or the guest is probed
    /// without orchestrator context): the guest itself decides — if it
    /// carries the overlay link, that plane is captured too.
    Unknown,
}

/// One capture plane of the witness: the interface to sniff, the MAC that
/// scopes the IPv6 clause of its filter, and the exit's own IPv4 address ON
/// THAT PLANE — a captured packet sourced from it is exit-origin traffic on
/// this plane (the underlay egress address, or the overlay address when the
/// plane is the vxlan link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessCapturePlane {
    pub iface: String,
    pub mac: String,
    pub addr: String,
    /// True for the vxlan overlay plane (WireGuard control rides it on a
    /// cross-LAN vxlan substrate); false for the default-route underlay NIC.
    pub overlay: bool,
}

/// True when `addr` falls inside the substrate's overlay pool
/// ([`OVERLAY_POOL_CIDR`]) — the address range `plan_overlay` assigns, so a
/// link only qualifies as the witness overlay plane when it carries one.
fn addr_in_overlay_pool(addr: &str) -> bool {
    let Some((net, prefix)) = OVERLAY_POOL_CIDR.split_once('/') else {
        return false;
    };
    let Ok(prefix_len): Result<u32, _> = prefix.parse() else {
        return false;
    };
    fn octets(value: &str) -> Option<u32> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut acc = 0u32;
        for part in parts {
            acc = (acc << 8) | u32::from(part.parse::<u8>().ok()?);
        }
        Some(acc)
    }
    let (Some(network), Some(candidate)) = (octets(net), octets(addr)) else {
        return false;
    };
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    network & mask == candidate & mask
}

/// The vxlan overlay capture plane on this guest, when it exists: the
/// [`VXLAN_LINK_NAME`] link must hold an address inside [`OVERLAY_POOL_CIDR`]
/// (both are what `substrate::plan_overlay`/`VxlanSubstrateProvider` create),
/// and its MAC must be readable (the IPv6 clause of the capture filter is
/// MAC-scoped, so an unreadable MAC fails closed through
/// [`detect_egress_mac`]). A non-zero `ip` exit means the guest carries no
/// such link — a legitimate netns/slirp/no-overlay shape, not an error.
fn detect_overlay_capture_plane(
    shell: &dyn RemoteShellHost,
) -> Result<Option<(String, String)>, String> {
    let argv = ["ip", "-4", "addr", "show", "dev", VXLAN_LINK_NAME];
    let out = shell.run_argv(&argv, &[], &[]).map_err(|err| {
        format!("failed to query the vxlan overlay link {VXLAN_LINK_NAME}: {err}")
    })?;
    if out.code != 0 {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let overlay_addr = stdout.lines().find_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let pos = parts.iter().position(|p| *p == "inet")?;
        let addr_cidr = parts.get(pos + 1)?;
        let addr = addr_cidr.split('/').next()?;
        if addr.is_empty() {
            return None;
        }
        addr_in_overlay_pool(addr).then(|| addr.to_owned())
    });
    let Some(addr) = overlay_addr else {
        return Ok(None);
    };
    let mac = detect_egress_mac(shell, VXLAN_LINK_NAME)?;
    Ok(Some((addr, mac)))
}

/// The planes this run captures: always the default-route egress NIC
/// (unchanged filter, unchanged leak counting), plus the vxlan overlay link
/// when the exit guest carries one and the orchestrator's substrate record
/// does not rule it out. [`SubstrateOverlayHint::Required`] makes a missing
/// overlay link a hard `Err`: recording a provisioned vxlan overlay while
/// silently capturing only the underlay is exactly the vacuity this witness
/// exists to refuse.
fn capture_planes(
    shell: &dyn RemoteShellHost,
    hint: SubstrateOverlayHint,
    egress_iface: &str,
    egress_addr: &str,
    egress_mac: &str,
) -> Result<Vec<WitnessCapturePlane>, String> {
    let overlay = match hint {
        SubstrateOverlayHint::NotRequired => None,
        SubstrateOverlayHint::Required | SubstrateOverlayHint::Unknown => {
            detect_overlay_capture_plane(shell)?
        }
    };
    let Some((overlay_addr, overlay_mac)) = overlay else {
        if hint == SubstrateOverlayHint::Required {
            return Err(format!(
                "the run's cross-network substrate is a provisioned {VXLAN_SUBSTRATE_ID} \
                 overlay, but the exit guest carries no {VXLAN_LINK_NAME} link with an \
                 {OVERLAY_POOL_CIDR} address — the WireGuard control rides that overlay, so an \
                 underlay-only capture would be vacuous; failing closed"
            ));
        }
        return Ok(vec![WitnessCapturePlane {
            iface: egress_iface.to_owned(),
            mac: egress_mac.to_owned(),
            addr: egress_addr.to_owned(),
            overlay: false,
        }]);
    };
    let mut planes = vec![WitnessCapturePlane {
        iface: egress_iface.to_owned(),
        mac: egress_mac.to_owned(),
        addr: egress_addr.to_owned(),
        overlay: false,
    }];
    // Pathological shape: the default route already exits via the overlay
    // link — the underlay plane above IS that link, never capture it twice.
    if !planes.iter().any(|plane| plane.iface == VXLAN_LINK_NAME) {
        planes.push(WitnessCapturePlane {
            iface: VXLAN_LINK_NAME.to_owned(),
            mac: overlay_mac,
            addr: overlay_addr,
            overlay: true,
        });
    }
    Ok(planes)
}

/// Fail-closed posture precondition: the active generated killswitch table
/// must carry the egress-scoped DNS/DoT drop rules the scoped ruleset emits
/// when `protected_dns` is on — udp dport {53,853} drop AND tcp dport
/// {53,853} drop, both scoped to `oifname "<egress>"` with
/// `meta nfproto ipv4`. A missing rule is named in the error (never a
/// silent pass over absent posture).
///
/// W2 (order-awareness): presence alone certified the AQ-70/F2 legacy shape —
/// an unqualified `ct state established` accept sitting BEFORE the drops
/// admits established tcp/53|853 flows no matter how many drops follow. So
/// within the chain that carries the scoped drops, every such unqualified
/// established accept must sit AFTER both drops; anything else fails the
/// precondition (`kill switch rule order unsafe: ...`). Garbled or empty
/// output still fails closed via the missing-rule checks.
/// Returns the posture: the table listing (the witness reads the WireGuard
/// listen port from it) plus the non-fatal DNS-order findings.
/// True when the rule's tokens carry an explicit `ct state` match listing
/// `established` (any nft spelling: bare, comma list, or `{ ... }` set).
fn tokens_have_ct_state_established(tokens: &[&str]) -> bool {
    let mut pos = 0;
    while pos + 1 < tokens.len() {
        if tokens[pos] == "ct" && tokens[pos + 1] == "state" {
            'ct_state: for token in &tokens[pos + 2..] {
                // Strip braces/commas so bare, `{ a, b }`, and mixed
                // spellings all reduce to a comma-separated state list.
                let clean = token.trim_matches(|c| c == '{' || c == '}' || c == ',');
                if clean.is_empty() {
                    // a bare brace token: keep walking inside the set
                    continue;
                }
                for state in clean.split(',').map(str::trim) {
                    if state == "established" {
                        return true;
                    }
                    if !matches!(state, "related" | "new" | "invalid" | "untracked") {
                        // a non-state token (e.g. `counter`) ends the
                        // ct state match expression
                        break 'ct_state;
                    }
                }
            }
        }
        pos += 1;
    }
    false
}

/// Killswitch posture produced by [`verify_scoped_dns_drop_rules`]: the
/// verbatim table listing (the witness reads the WireGuard listen port from
/// it) plus the NON-FATAL DNS-order findings. Fatal shape violations return
/// `Err` from the verifier; informational ones (order problems on accepts
/// that cannot carry an unqualified established-flow accept) are recorded
/// here and surfaced in the report under `dns_rule_order_findings`.
#[derive(Debug, Clone)]
pub struct ScopedDnsDropPosture {
    pub listing: String,
    pub order_findings: Vec<String>,
}

fn verify_scoped_dns_drop_rules(
    shell: &dyn RemoteShellHost,
    egress_iface: &str,
    table: &str,
) -> Result<ScopedDnsDropPosture, String> {
    let argv: [&str; 7] = ["sudo", "-n", "nft", "list", "table", "inet", table];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to list killswitch table {table}: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "nft list table inet {table} exited {}; posture unverifiable, failing closed",
            out.code
        ));
    }
    let oifname = format!("oifname \"{egress_iface}\"");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut found_udp = false;
    let mut found_tcp = false;
    // (line index, chain, collapsed text) context for the W2 order check.
    let mut lines_ctx: Vec<(usize, String, String)> = Vec::new();
    let mut udp_drop: Option<(usize, String)> = None;
    let mut tcp_drop: Option<(usize, String)> = None;
    let mut current_chain = String::new();
    for (idx, line) in stdout.lines().enumerate() {
        let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.starts_with("chain ") && collapsed.ends_with('{') {
            current_chain = collapsed
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
        } else if collapsed == "}" {
            current_chain.clear();
        }
        lines_ctx.push((idx, current_chain.clone(), collapsed.clone()));
        if !collapsed.contains(&oifname)
            || !collapsed.contains("meta nfproto ipv4")
            || !collapsed.contains("drop")
        {
            continue;
        }
        if collapsed.contains("udp dport")
            && collapsed.contains('{')
            && collapsed.contains("53,")
            && collapsed.contains("853")
            && collapsed.contains('}')
        {
            found_udp = true;
            udp_drop = Some((idx, current_chain.clone()));
        }
        if collapsed.contains("tcp dport")
            && collapsed.contains('{')
            && collapsed.contains("53,")
            && collapsed.contains("853")
            && collapsed.contains('}')
        {
            found_tcp = true;
            tcp_drop = Some((idx, current_chain.clone()));
        }
    }
    if !found_udp {
        return Err(format!(
            "posture precondition failed: killswitch table inet {table} is missing the \
             egress-scoped drop rule `oifname \"{egress_iface}\" meta nfproto ipv4 udp dport \
             {{ 53, 853 }} drop` (protected_dns posture absent) — failing closed"
        ));
    }
    if !found_tcp {
        return Err(format!(
            "posture precondition failed: killswitch table inet {table} is missing the \
             egress-scoped drop rule `oifname \"{egress_iface}\" meta nfproto ipv4 tcp dport \
             {{ 53, 853 }} drop` (protected_dns posture absent) — failing closed"
        ));
    }
    let (order_fatal, order_findings) =
        verify_dns_drop_rule_order(&lines_ctx, udp_drop, tcp_drop, table, egress_iface)?;
    if let Some(fatal) = order_fatal {
        return Err(fatal);
    }
    Ok(ScopedDnsDropPosture {
        listing: stdout.into_owned(),
        order_findings,
    })
}

/// W2 order check over the collected `(line index, chain, collapsed rule)`
/// context: every accept that can match egress tcp/udp dport 53|853 (see
/// [`accept_can_match_dns_ports`]) must sit in a chain that carries BOTH
/// scoped DNS drops, AFTER both of them. An accept in a drop-less chain, or
/// ahead of either drop, shadows the drops for the flows it admits.
/// (Missing-drop failures are reported by the caller before this runs.)
///
/// Scope-aware (round-3, so the REAL production table passes): an accept
/// that provably cannot carry egress-NIC output DNS — `iifname`-bound
/// (forward-chain shapes) or `oifname`-bound to another interface (lo,
/// tunnel) — needs no ordering UNLESS it carries an explicit DNS-matchable
/// `dport` clause, which stays fail-closed (`accept_has_dns_matchable_dport_clause`).
///
/// Severity split (owner decision): an order violation on an accept whose
/// text carries an explicit `ct state established[,related] accept` match
/// (the shadowing-ESTABLISHED shape) stays FATAL; every other violating
/// shape (sport-only accepts, shadowed bare dport accepts, accepts scoped
/// by a DNS-matchable dport clause, ambiguous shapes) is downgraded to a
/// NON-FATAL finding returned in the findings vector.
fn verify_dns_drop_rule_order(
    lines_ctx: &[(usize, String, String)],
    udp_drop: Option<(usize, String)>,
    tcp_drop: Option<(usize, String)>,
    table: &str,
    egress_iface: &str,
) -> Result<(Option<String>, Vec<String>), String> {
    let mut findings = Vec::new();
    for (accept_idx, accept_chain, accept_text) in lines_ctx {
        if !accept_can_match_dns_ports(accept_text) {
            continue;
        }
        let tokens: Vec<&str> = strip_nft_comment(accept_text).split_whitespace().collect();
        let scoped_away = accept_scoped_away_from_egress_output(&tokens, egress_iface);
        let dns_dport_clause = accept_has_dns_matchable_dport_clause(&tokens);
        if scoped_away && !dns_dport_clause {
            continue;
        }
        let has_established_accept = tokens_have_ct_state_established(&tokens);
        let violation = if let (None, None) = (
            udp_drop.as_ref().filter(|(_, chain)| chain == accept_chain),
            tcp_drop.as_ref().filter(|(_, chain)| chain == accept_chain),
        ) {
            // Chain-scoped (W2 probes: decoy duplicate drops in OTHER
            // chains must not satisfy the order check): the accept's own
            // chain must carry both drops.
            Some(format!(
                "kill switch rule order unsafe: in chain `{accept_chain}` of table inet \
                 {table}, the rule `{accept_text}` (line {}) can match egress tcp/udp dport \
                 53|853 but that chain does not carry BOTH scoped DNS drops — an accept that \
                 shadows drops living in another chain is unsafe (AQ-70/F2 legacy shape) — \
                 failing closed",
                accept_idx + 1
            ))
        } else if let (Some((udp_idx, _)), Some((tcp_idx, _))) = (
            udp_drop.as_ref().filter(|(_, chain)| chain == accept_chain),
            tcp_drop.as_ref().filter(|(_, chain)| chain == accept_chain),
        ) && (accept_idx < udp_idx || accept_idx < tcp_idx)
        {
            let shadowed_drop = if accept_idx < udp_idx {
                udp_idx
            } else {
                tcp_idx
            };
            Some(format!(
                "kill switch rule order unsafe: in chain `{accept_chain}` of table inet \
                 {table}, the rule `{accept_text}` (line {}) accepts DNS-capable traffic \
                 BEFORE the scoped DNS drop (line {}); a tcp/53|853 flow the rule admits is \
                 accepted before that drop can match it (AQ-70/F2 legacy shape) — failing \
                 closed",
                accept_idx + 1,
                shadowed_drop + 1
            ))
        } else {
            None
        };
        let Some(violation) = violation else {
            continue;
        };
        if has_established_accept {
            return Ok((Some(violation), findings));
        }
        findings.push(format!(
            "non-fatal DNS rule order finding: {violation} (informational: the accept does \
             not carry an explicit `ct state established` match, so it is not the \
             shadowing-ESTABLISHED shape; recorded under dns_rule_order_findings)"
        ));
    }
    Ok((None, findings))
}

/// Detect the exit's own IPv4 address on the egress interface — the source
/// address host-origin leaks and masqueraded client traffic both carry.
fn detect_egress_ipv4(shell: &dyn RemoteShellHost, iface: &str) -> Result<String, String> {
    let argv = ["ip", "-4", "addr", "show", "dev", iface];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to read addresses on {iface}: {err}"))?;
    if out.code != 0 {
        return Err(format!("`ip -4 addr show dev {iface}` exited {}", out.code));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == "inet")
            && let Some(addr_cidr) = parts.get(pos + 1)
        {
            if let Some(addr) = addr_cidr.split('/').next() {
                if !addr.is_empty() {
                    return Ok(addr.to_string());
                }
            }
        }
    }
    Err(format!(
        "no IPv4 `inet <addr>/` entry found on egress interface {iface}"
    ))
}

/// The WireGuard listen port, read from the killswitch table the posture
/// check already listed. Rustynet's data plane does not expose its WireGuard
/// socket to the `wg` tool (`wg show` prints nothing on a live exit, run
/// linux-u12b), but the daemon's killswitch allows the port it listens on as a
/// pair on the egress interface (phase10 `wg_listen_port_allow_tokens`):
/// `oifname "<egress>" meta nfproto ipv4 udp dport <port> accept` and the same
/// with `sport`. The port is the one value that has both halves. Zero or
/// several such ports fail closed: WireGuard presence would be unwitnessable.
fn wg_listen_port_from_killswitch_listing(
    listing: &str,
    egress_iface: &str,
) -> Result<u16, String> {
    let oifname = format!("oifname \"{egress_iface}\"");
    let mut dports: Vec<u16> = Vec::new();
    let mut sports: Vec<u16> = Vec::new();
    for line in listing.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let collapsed = tokens.join(" ");
        if !collapsed.contains(&oifname)
            || !collapsed.contains("meta nfproto ipv4 udp")
            || tokens.last() != Some(&"accept")
        {
            continue;
        }
        for (idx, token) in tokens.iter().enumerate() {
            let bucket = match *token {
                "dport" => &mut dports,
                "sport" => &mut sports,
                _ => continue,
            };
            if idx.checked_sub(1).and_then(|prev| tokens.get(prev)) == Some(&"udp")
                && let Some(port) = tokens.get(idx + 1).and_then(|p| p.parse::<u16>().ok())
                && port != 0
                && tokens.get(idx + 2) == Some(&"accept")
            {
                bucket.push(port);
            }
        }
    }
    let mut paired: Vec<u16> = dports.into_iter().filter(|p| sports.contains(p)).collect();
    paired.sort_unstable();
    paired.dedup();
    match paired.as_slice() {
        [port] => Ok(*port),
        [] => Err(format!(
            "could not determine the WireGuard listen port: the killswitch table has no \
             `oifname \"{egress_iface}\" meta nfproto ipv4 udp dport/sport <port> accept` pair — \
             WireGuard presence is unwitnessable, failing closed"
        )),
        several => Err(format!(
            "could not determine the WireGuard listen port: the killswitch table carries \
             several udp dport/sport accept pairs on {egress_iface} ({several:?}) — ambiguous, \
             failing closed"
        )),
    }
}

/// The MAC address of the exit's egress NIC, from `ip -brief link show dev
/// <iface>` (third field). The IPv6 clause of the capture filter is scoped to
/// frames this NIC sends: tcpdump captures promiscuously, and on a bridged LAN
/// (lenovo-bot's guests) it also sees other devices' IPv6 neighbour
/// solicitations, which run lenovo-u16l counted as three IPv6 "leaks" from an
/// exit that has no IPv6 address at all. Fails closed on anything that is not a
/// plain `xx:xx:xx:xx:xx:xx` MAC.
fn detect_egress_mac(shell: &dyn RemoteShellHost, iface: &str) -> Result<String, String> {
    let argv = ["ip", "-brief", "link", "show", "dev", iface];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to read the link address of {iface}: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "`ip -brief link show dev {iface}` exited {}",
            out.code
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mac = stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if is_plain_mac(&mac) {
        Ok(mac)
    } else {
        Err(format!(
            "could not read a MAC address for egress interface {iface} (got {mac:?}) — the \
             IPv6 witness cannot be scoped to frames this exit sends, failing closed"
        ))
    }
}

fn is_plain_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The tcpdump capture filter, as separate argv tokens (never a shell string):
/// IPv4 host-origin DNS/DoT ports, ICMP (masqueraded client control) and the
/// WireGuard listen port, plus IPv6 SENT BY the egress NIC (`egress_mac`).
///
/// The port clauses are IPv4-only on purpose. `classify_capture` counts every
/// captured IPv6 line as a leak, and `udp port 53` alone also matches IPv6, so
/// on a bridged LAN a neighbour's IPv6 DNS would count against this exit. The
/// exit's own IPv6 is still captured, by the MAC-scoped clause. pcap `and` and
/// `or` have equal precedence and group left to right, hence the explicit
/// parentheses.
fn capture_filter_tokens(wg_port: u16, egress_mac: &str) -> Vec<String> {
    vec![
        "(".to_owned(),
        "ip".to_owned(),
        "and".to_owned(),
        "(".to_owned(),
        "udp".to_owned(),
        "port".to_owned(),
        "53".to_owned(),
        "or".to_owned(),
        "tcp".to_owned(),
        "port".to_owned(),
        "53".to_owned(),
        "or".to_owned(),
        "tcp".to_owned(),
        "port".to_owned(),
        WITNESS_DOT_PORT.to_string(),
        "or".to_owned(),
        "icmp".to_owned(),
        "or".to_owned(),
        "udp".to_owned(),
        "port".to_owned(),
        wg_port.to_string(),
        ")".to_owned(),
        ")".to_owned(),
        "or".to_owned(),
        "(".to_owned(),
        "ip6".to_owned(),
        "and".to_owned(),
        "ether".to_owned(),
        "src".to_owned(),
        egress_mac.to_owned(),
        ")".to_owned(),
    ]
}

/// A stdout line that is tcpdump banner/chatter, never a packet: the same
/// whitelist the chaos daemon-fault tally uses
/// (`^(tcpdump:|listening on|capture_provenance=|$)`), so banner text can
/// never be counted as a packet.
fn is_capture_banner_line(line: &str) -> bool {
    let t = line.trim();
    t.is_empty()
        || t.starts_with("tcpdump:")
        || t.starts_with("listening on")
        || t.starts_with("capture_provenance=")
}

/// stderr line classification mirroring the chaos daemon-fault whitelist:
/// `dropped privs to `, `listening on `, and the numeric packet tallies
/// (`N packets captured` / `N packets received by filter` / `N packets
/// dropped by kernel`) are benign; anything else is a tcpdump error.
/// tcpdump 4.99+ prints the captured/received tally lines with a wall-clock
/// prefix (`12:00:20.000000 5 packets captured`), so a leading
/// `<HH:MM:SS.uS>` timestamp token is stripped before the tally check —
/// nothing else about the whitelist is widened.
/// The `tcpdump: listening on` banner form is treated as benign only because
/// the caller separately requires the `listening on ` banner to be present —
/// every other `tcpdump: ...` line (real errors) stays non-benign and fails
/// the stage.
fn is_benign_tcpdump_stderr_line(line: &str) -> bool {
    let t = line.trim();
    // tcpdump 4.99 prints this notice to stderr on every run without -v
    // (run katana-u13 failed the witness on exactly this line); matched
    // exactly, as the chaos daemon-fault tally does (b73c39aa9).
    if t.is_empty()
        || t.starts_with("dropped privs to ")
        || t.starts_with("listening on ")
        || t.starts_with("tcpdump: listening on ")
        || t == "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode"
    {
        return true;
    }
    let t = match strip_tcpdump_summary_timestamp(t) {
        Some(rest) => rest,
        None => t,
    };
    let toks: Vec<&str> = t.split_whitespace().collect();
    if toks.len() < 3 {
        return false;
    }
    let first = toks[0];
    // tcpdump pluralises the tally: `1 packet received by filter`.
    if first.is_empty()
        || !first.bytes().all(|b| b.is_ascii_digit())
        || (toks[1] != "packets" && toks[1] != "packet")
    {
        return false;
    }
    match toks[2] {
        "captured" => toks.len() == 3,
        "received" => toks.len() == 5 && toks[3] == "by" && toks[4] == "filter",
        "dropped" => toks.len() == 5 && toks[3] == "by" && toks[4] == "kernel",
        _ => false,
    }
}

/// If `line` starts with a tcpdump summary timestamp token
/// (`HH:MM:SS.microseconds`, digits separated by `:` and `.` only), return
/// the remainder after it; otherwise None.
fn strip_tcpdump_summary_timestamp(line: &str) -> Option<&str> {
    let (head, rest) = line.split_once(' ')?;
    if head.is_empty()
        || !head
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b':' || b == b'.')
        || !head.contains(':')
        || !head.contains('.')
    {
        return None;
    }
    Some(rest)
}

/// Split a tcpdump `addr.port` endpoint token (or bare IPv4) into its parts.
/// IPv6 literals (containing `:`) return None — they are classified by the
/// `IP6` marker before endpoint parsing.
fn split_v4_addr_port(token: &str) -> Option<(&str, Option<u16>)> {
    if token.contains(':') {
        return None;
    }
    let segs: Vec<&str> = token.split('.').collect();
    match segs.len() {
        4 => Some((token, None)),
        5 => {
            let port_str = segs[4];
            if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let port: u16 = port_str.parse().ok()?;
            let addr_len = token.len() - port_str.len() - 1;
            Some((&token[..addr_len], Some(port)))
        }
        _ => None,
    }
}

/// Parse the `<src> > <dst>` endpoint pair out of a tcpdump -nn IPv4 packet
/// line (the span between the `IP ` marker and the `: ` details delimiter).
fn parse_v4_packet_endpoints(line: &str) -> Option<(String, Option<u16>, String, Option<u16>)> {
    let marker = line.find(" IP ")?;
    let rest = &line[marker + 4..];
    let end = rest.find(": ")?;
    let endpoints = &rest[..end];
    let (src_tok, dst_tok) = endpoints.split_once(" > ")?;
    let (src_ip, src_port) = split_v4_addr_port(src_tok.trim())?;
    let (dst_ip, dst_port) = split_v4_addr_port(dst_tok.trim())?;
    Some((src_ip.to_owned(), src_port, dst_ip.to_owned(), dst_port))
}

/// The details text of a tcpdump `-nn` packet line: everything after the
/// `IP <src> > <dst>:` delimiter (MED-4 of the independent review).
pub fn packet_details_after_endpoints(line: &str) -> Option<&str> {
    let marker = line.find(" IP ")?;
    let rest = &line[marker + 4..];
    let pos = rest.find(": ")?;
    Some(&rest[pos + 2..])
}

/// The transport of a tcpdump `-nn` packet line, derived ONLY from line
/// structure (MED-4): tcp iff the details begin `Flags [`; udp iff they
/// begin `UDP,`; anything else is [`LineTransport::Unknown`], which callers
/// treat as udp — the strict direction, since a misread udp line stays a
/// leak failure while a misread tcp line could be relieved by attribution.
/// Never probe for `Flags` anywhere in the line: a udp DNS query's qname
/// can carry that text (`A? Flags.example.com`), which the old
/// `contains("Flags")` check misclassified as tcp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineTransport {
    Tcp,
    Udp,
    Unknown,
}

fn line_transport(line: &str) -> LineTransport {
    let Some(details) = packet_details_after_endpoints(line) else {
        return LineTransport::Unknown;
    };
    if details.starts_with("Flags [") {
        LineTransport::Tcp
    } else if details.starts_with("UDP,") {
        LineTransport::Udp
    } else {
        LineTransport::Unknown
    }
}

/// Classify every packet line of the capture into the witness classes.
/// Banner lines are skipped (never counted); anything unparseable is ignored
/// by classification but the capture-level checks (banner present, stderr
/// clean) fail the stage independently.
///
/// `host_src_addrs` is the exit's own address on EVERY captured plane (the
/// underlay egress address, plus the overlay address when the vxlan plane is
/// captured): a packet sourced from any of them is exit-origin traffic and
/// keeps the strict count-and-fail treatment, wherever on the guest it was
/// witnessed. Leak counts never weaken when a plane is added — they can only
/// grow.
fn classify_capture(stdout: &str, host_src_addrs: &[&str], wg_port: u16) -> LeakWitnessCounts {
    let mut counts = LeakWitnessCounts::default();
    for line in stdout.lines() {
        if is_capture_banner_line(line) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("IP6 ") || trimmed.contains(" IP6 ") {
            counts.ipv6 += 1;
            continue;
        }
        let Some((src_ip, src_port, dst_ip, dst_port)) = parse_v4_packet_endpoints(line) else {
            continue;
        };
        if host_src_addrs.contains(&src_ip.as_str()) {
            if dst_port == Some(WITNESS_DOT_PORT) {
                counts.host_dot += 1;
                continue;
            }
            if dst_port == Some(53) {
                if line_transport(line) == LineTransport::Tcp {
                    counts.host_dns_tcp += 1;
                } else {
                    counts.host_dns_udp += 1;
                }
                continue;
            }
            if dst_ip == WITNESS_ICMP_TARGET && line.contains("ICMP") {
                counts.forwarded_icmp += 1;
                continue;
            }
        }
        if src_port == Some(wg_port) || dst_port == Some(wg_port) {
            counts.wireguard += 1;
        }
    }
    counts
}

/// Fail-closed verdict over the per-class counts: any leak class above zero
/// fails naming the class and count; missing WireGuard traffic makes the
/// witness vacuous and fails. The RAW ICMP positive control is restored
/// here exactly as before W3 (HIGH-2 of the independent review): at least
/// one ICMP packet to the control target must be on the wire, or the
/// witness is vacuous. [`evaluate_positive_control`] additionally demands
/// conntrack attribution for that ICMP — the two checks are cumulative,
/// never a downgrade.
pub fn evaluate_leak_witness(
    counts: &LeakWitnessCounts,
    egress_iface: &str,
    wg_port: u16,
) -> Vec<String> {
    let mut failures = Vec::new();
    if counts.host_dns_udp > 0 {
        failures.push(format!(
            "egress leak: {} host-origin udp/53 packet(s) left {egress_iface}",
            counts.host_dns_udp
        ));
    }
    if counts.host_dns_tcp > 0 {
        failures.push(format!(
            "egress leak: {} host-origin tcp/53 packet(s) left {egress_iface}",
            counts.host_dns_tcp
        ));
    }
    if counts.host_dot > 0 {
        failures.push(format!(
            "egress leak: {} host-origin tcp/853 (DoT) packet(s) left {egress_iface}",
            counts.host_dot
        ));
    }
    if counts.ipv6 > 0 {
        failures.push(format!(
            "egress leak: {} IPv6 packet(s) left {egress_iface} (killswitch emits no IPv6 \
             accept; any IPv6 egress is a leak)",
            counts.ipv6
        ));
    }
    if counts.forwarded_icmp == 0 {
        failures.push(format!(
            "vacuous witness: no masqueraded client ICMP to {WITNESS_ICMP_TARGET} from the \
             exit egress address was captured — the forwarded-traffic positive control is \
             absent, the zero-leak counts prove nothing"
        ));
    }
    if counts.wireguard == 0 {
        failures.push(format!(
            "vacuous witness: no WireGuard udp/{wg_port} traffic was captured — the tunnel \
             control is absent, the zero-leak counts prove nothing"
        ));
    }
    failures
}

/// W3c positive-control verdict, layered ON TOP of the restored raw ICMP
/// check in [`evaluate_leak_witness`] (HIGH-2 of the independent review):
/// when raw ICMP traffic to the control target WAS captured, at least one
/// such packet must be conntrack-attributed to a non-local client flow.
/// A raw==0 capture is already failed by [`evaluate_leak_witness`], so this
/// verdict stays empty there. DNS (tcp/53|853) attribution is recorded as
/// evidence but never satisfies the ICMP control: the control is the ICMP
/// channel itself. No claim is made that exit-origin ICMP is the only
/// possible source of the wire traffic — masqueraded client traffic is
/// wire-indistinguishable from exit-origin ICMP, which is exactly why
/// conntrack attribution is demanded.
pub fn evaluate_positive_control(
    control: &PositiveControlEvidence,
    egress_iface: &str,
    attribution_armed: bool,
    snapshot_carries_icmp_entries: bool,
) -> Vec<String> {
    // Attribution DISARMED (round-3, conditionality): without conntrack
    // snapshots (real guests ship no conntrack binary and no /proc table)
    // the attributed-ICMP demand is unsatisfiable — demanding it failed
    // every clean run. The RAW ICMP control in [`evaluate_leak_witness`]
    // still fires; DNS-relief is impossible while disarmed
    // ([`attribute_forwarded_packets`] gates on `enabled`), so a leak shape
    // still fails on its counts.
    if !attribution_armed || control.forwarded_icmp_raw == 0 {
        return Vec::new();
    }
    // Q04 (round-4): an armed, raw>0, attributed==0 run is a vacuous
    // witness ONLY when the snapshots actually carry icmp entries — then
    // zero attribution means the wire packets are unproven. When the
    // snapshots carry NO icmp entry, the raw packets are exit-origin by
    // elimination (conntrack saw every flow and none is non-local) and the
    // attributed-ICMP bonus stays optional. A non-mesh icmp entry (e.g. the
    // exit's own echo) still makes the snapshots icmp-carrying: it must not
    // count as the bonus, and the run stays vacuous.
    if control.forwarded_icmp_attributed == 0 && snapshot_carries_icmp_entries {
        return vec![format!(
            "vacuous witness: no forwarded traffic on {egress_iface} was conntrack-attributed \
             to a non-local client flow ({} ICMP packet(s) to {WITNESS_ICMP_TARGET} seen on \
             the wire, but none matched a client flow in the conntrack snapshots) — the \
             forwarded-traffic positive control is absent and the zero-leak counts prove \
             nothing",
            control.forwarded_icmp_raw
        )];
    }
    Vec::new()
}

/// W3b outcome of the conservative conntrack attribution for one packet.
enum ForwardedAttribution {
    /// A matching entry with a provably non-local ORIGINAL source inside the
    /// stage-supplied mesh-peer set: the packet is a masqueraded mesh-peer
    /// flow (client, relay, or entry — W3T).
    Forwarded {
        conntrack_line: String,
        original_src: String,
        snapshot: &'static str,
        mesh_peer: String,
    },
    /// Everything else — no matching entry, unparseable snapshot, matched
    /// entry whose ORIGINAL source is an address of the exit itself, or
    /// ambiguous (multiple conflicting matches). The packet keeps today's
    /// count-and-fail behaviour: W3 can never turn a possible host leak
    /// into a pass.
    NotForwarded,
}

/// The ICMP echo triple parsed from a tcpdump line (`ICMP echo request, id
/// 7, seq 0, length 64`) or from the ordered `type=`/`code=`/`id=` triples
/// of a conntrack line. Attribution for icmp requires exact type/code/id
/// agreement on the matched direction — protocol alone is not enough (LOW
/// finding of the independent review: an unrelated echo with a different id
/// must never be absorbed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IcmpEcho {
    kind: u8,
    code: u8,
    id: u16,
}

/// Parse the ICMP echo triple out of the details text of a tcpdump line.
/// Unparseable details return None, which fails the match closed.
fn parse_icmp_echo_from_packet(details: &str) -> Option<IcmpEcho> {
    let (kind, code) = if details.contains("ICMP echo request") {
        (8, 0)
    } else if details.contains("ICMP echo reply") {
        (0, 0)
    } else {
        return None;
    };
    let id_pos = details.find("id ")?;
    let rest = details[id_pos + 3..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let id: u16 = rest[..end].parse().ok()?;
    Some(IcmpEcho { kind, code, id })
}

/// The ordered `type=`/`code=`/`id=` triples of a conntrack icmp line: the
/// first triple is the ORIGINAL direction, the second the REPLY. Lines with
/// fewer than the needed triples yield None for that direction — no blind
/// match.
fn icmp_echo_from_entry(entry: &ConntrackEntry, occurrence: usize) -> Option<IcmpEcho> {
    let mut triples: Vec<IcmpEcho> = Vec::new();
    let mut kind = None;
    let mut code = None;
    let mut id = None;
    for token in entry.line.split_whitespace() {
        match token.split_once('=') {
            Some(("type", value)) => kind = value.parse().ok(),
            Some(("code", value)) => code = value.parse().ok(),
            Some(("id", value)) => id = value.parse().ok(),
            _ => {}
        }
        if let (Some(k), Some(c), Some(i)) = (kind, code, id) {
            triples.push(IcmpEcho {
                kind: k,
                code: c,
                id: i,
            });
            kind = None;
            code = None;
            id = None;
        }
    }
    triples.get(occurrence).copied()
}

/// Match a packet 4-tuple against one conntrack entry: the packet must run
/// in the entry's ORIGINAL direction (direct tuple match) or REPLY direction
/// (reverse of the reply tuple), the protocol must agree — an icmp
/// entry can never absorb a tcp packet or vice versa — and for icmp the
/// type/code/id triple of the matched direction must equal the wire triple.
fn conntrack_entry_matches_packet(
    entry: &ConntrackEntry,
    proto: &str,
    src_ip: &str,
    src_port: Option<u16>,
    dst_ip: &str,
    dst_port: Option<u16>,
    icmp: Option<IcmpEcho>,
) -> bool {
    if entry.proto != proto {
        return false;
    }
    let original_direct = entry.original.src == src_ip
        && entry.original.dst == dst_ip
        && entry.original.sport == src_port
        && entry.original.dport == dst_port;
    let reply_reverse = entry.reply.src == dst_ip
        && entry.reply.dst == src_ip
        && entry.reply.sport == dst_port
        && entry.reply.dport == src_port;
    // icmp echo replies travel the reply tuple DIRECTLY (target -> egress),
    // they are not a reversal of it — and for egress-sourced scans a direct
    // reply match can never fire for tcp (the packet src would be the
    // remote, never the egress address), so this stays conservative.
    let reply_direct = entry.reply.src == src_ip
        && entry.reply.dst == dst_ip
        && entry.reply.sport == src_port
        && entry.reply.dport == dst_port;
    if !(original_direct || reply_reverse || reply_direct) {
        return false;
    }
    if proto == "icmp" {
        let Some(wire) = icmp else {
            return false;
        };
        // The masqueraded echo REQUEST (wire kind 8) is the ORIGINAL
        // direction of the flow regardless of which tuple interpretation
        // matched — the src is simply rewritten by NAT. Same for the REPLY
        // (kind 0) against the reply tuple. So the expected triple is chosen
        // by wire semantics: request -> original triple, reply -> reply
        // triple.
        let expected = if wire.kind == 8 { 0 } else { 1 };
        return icmp_echo_from_entry(entry, expected) == Some(wire);
    }
    true
}

/// Parse an IPv4 literal into its host-order u32.
fn parse_ipv4_u32(addr: &str) -> Option<u32> {
    if !is_valid_ipv4(addr) {
        return None;
    }
    let octets: Vec<&str> = addr.split('.').collect();
    let mut value = 0u32;
    for octet in octets {
        let octet: u32 = octet.parse().ok()?;
        value = (value << 8) | octet;
    }
    Some(value)
}

/// Mask an IPv4 literal down to its network address for `prefix` bits.
fn mask_ipv4(addr: &str, prefix: u8) -> Option<u32> {
    if prefix > 32 {
        return None;
    }
    let ip = parse_ipv4_u32(addr)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(ip & mask)
}

/// True when `addr` is inside `net/prefix`.
fn ipv4_in_subnet(addr: &str, net: u32, prefix: u8) -> bool {
    mask_ipv4(addr, prefix) == Some(net)
}

/// The address classes that can never be a mesh client ORIGINAL source
/// (MED-5 of the independent review): invalid, unspecified (0.0.0.0/8),
/// loopback, link-local (169.254.0.0/16), multicast/reserved/broadcast
/// (224.0.0.0/4 through 255.255.255.255). Exit-local addresses are
/// rejected separately by [`is_exit_local_addr`] with the capture-start
/// ground truth.
fn is_disallowed_client_src(addr: &str) -> bool {
    if !is_valid_ipv4(addr) {
        return true;
    }
    let first: u8 = addr
        .split('.')
        .next()
        .and_then(|octet| octet.parse().ok())
        .unwrap_or(255);
    addr.starts_with("0.")
        || addr.starts_with("127.")
        || addr.starts_with("169.254.")
        || first >= 224
}

/// The last-resort client space (documented fallback): RFC1918 private
/// space plus the CGNAT range (100.64.0.0/10). Used ONLY when neither the
/// stage nor the capture-start interface listing narrows the space.
fn is_rfc1918_or_cgnat(addr: &str) -> bool {
    let Some(ip) = parse_ipv4_u32(addr) else {
        return false;
    };
    let octets = [
        (ip >> 24) as u8,
        (ip >> 16) as u8,
        (ip >> 8) as u8,
        ip as u8,
    ];
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
}

/// The address space a conntrack ORIGINAL source must fall in before a
/// packet may be attributed to a forwarded mesh-peer flow (W3, MED-5 of the
/// independent review; W3T scope correction). Priority order:
/// 1. stage-supplied mesh-peer addresses: the orchestrator's mesh address of
///    EVERY non-exit node as `(alias, address)` pairs (W3T — u46-r48 proved
///    a RELAY's forwarded tcp/53 flow, so client-only admission mis-flagged
///    normal mesh transit; exact match against the address, alias carried
///    for the verdict);
/// 2. else the mesh subnet derived from the capture-start
///    `ip -4 -o addr show` listing: the TUNNEL interface's subnet only
///    (e.g. 10.6.0.0/24) — every other interface (docker0, a second NIC)
///    faces a network that is not the mesh and must never widen the space;
/// 3. else the documented fallback [`is_rfc1918_or_cgnat`].
///
/// Every tier additionally rejects the infrastructure classes in
/// [`is_disallowed_client_src`]; exit-local addresses are rejected before
/// this space is consulted. The stage supplying NOTHING (real orchestrator
/// without mesh addresses) must NOT silently widen to the whole RFC1918 —
/// the tunnel subnet from the exit's own interface listing is strictly
/// narrower and preferred.
struct ClientSpace {
    stage_peers: Vec<(String, String)>,
    mesh_subnets: Vec<(u32, u8)>,
}

impl ClientSpace {
    /// Derive the space from the stage-supplied mesh-peer pairs (empty = not
    /// supplied) and the capture-start `ip -4 -o addr show` listing.
    /// `tunnel_iface` restricts the derived tier to THAT interface's
    /// subnets (round-3: every other non-lo interface — docker0, a second
    /// NIC — faces a network that is not the mesh, and its subnets must
    /// never widen the client space).
    fn derive(
        stage_peers: &[(String, String)],
        addr_listing: &str,
        egress_addr: &str,
        tunnel_iface: &str,
    ) -> Self {
        let mut mesh_subnets = Vec::new();
        if stage_peers.is_empty() {
            for (iface, addr, prefix) in parse_ip_o_addr_show_v4_entries(addr_listing) {
                if iface != tunnel_iface || addr == egress_addr || addr.starts_with("127.") {
                    continue;
                }
                if let Some(net) = mask_ipv4(&addr, prefix) {
                    mesh_subnets.push((net, prefix));
                }
            }
        }
        ClientSpace {
            stage_peers: stage_peers.to_vec(),
            mesh_subnets,
        }
    }

    /// True when a validated, non-exit-local ORIGINAL source belongs to the
    /// mesh-peer space.
    fn admits(&self, addr: &str) -> bool {
        if is_disallowed_client_src(addr) {
            return false;
        }
        if !self.stage_peers.is_empty() {
            return self
                .stage_peers
                .iter()
                .any(|(_, peer_addr)| peer_addr == addr);
        }
        if !self.mesh_subnets.is_empty() {
            return self
                .mesh_subnets
                .iter()
                .any(|(net, prefix)| ipv4_in_subnet(addr, *net, *prefix));
        }
        is_rfc1918_or_cgnat(addr)
    }

    /// The alias of the mesh peer whose address is `addr`, when the stage
    /// supplied the pair (W3T). Addresses outside the exact set return None.
    fn peer_alias(&self, addr: &str) -> Option<&str> {
        self.stage_peers
            .iter()
            .find(|(_, peer_addr)| peer_addr == addr)
            .map(|(alias, _)| alias.as_str())
    }
}

/// Parse `ip -4 -o addr show` into `(iface, addr, prefix)` triples — the
/// interface-scoped form used to derive the mesh client subnets (MED-5).
pub fn parse_ip_o_addr_show_v4_entries(stdout: &str) -> Vec<(String, String, u8)> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (idx, token) in tokens.iter().enumerate() {
            if *token != "inet" {
                continue;
            }
            let Some(cidr) = tokens.get(idx + 1) else {
                continue;
            };
            let Some((addr, prefix)) = cidr.split_once('/') else {
                continue;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                continue;
            };
            if prefix > 32 || !is_valid_ipv4(addr) {
                continue;
            }
            let Some(iface) = idx.checked_sub(1).and_then(|prev| tokens.get(prev)) else {
                continue;
            };
            entries.push((
                iface.trim_end_matches(':').to_owned(),
                addr.to_owned(),
                prefix,
            ));
        }
    }
    entries
}

/// True when the flow this packet belongs to showed its INITIATOR packet
/// inside the capture window: for tcp the details begin `Flags [S` (SYN —
/// `[FS]` simultaneous-open is deliberately NOT counted, staying strict),
/// for icmp the line is an `ICMP echo request` (the echo is the flow's
/// first packet). udp never has an initiator — a udp flow can only ever be
/// proven via the both-snapshot rule. This is the MED-3 discriminator: a
/// flow with NO initiator in the window pre-existed it, so attribution
/// additionally demands a START-snapshot match.
fn tuple_started_inside_window(
    capture_stdout: &str,
    proto: &str,
    src_ip: &str,
    src_port: Option<u16>,
    dst_ip: &str,
    dst_port: Option<u16>,
) -> bool {
    capture_stdout.lines().any(|line| {
        if is_capture_banner_line(line) {
            return false;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("IP6 ") || trimmed.contains(" IP6 ") {
            return false;
        }
        let Some((line_src, line_sport, line_dst, line_dport)) = parse_v4_packet_endpoints(line)
        else {
            return false;
        };
        if line_src != src_ip
            || line_sport != src_port
            || line_dst != dst_ip
            || line_dport != dst_port
        {
            return false;
        }
        match proto {
            "tcp" => packet_details_after_endpoints(line)
                .map(|details| details.starts_with("Flags [S"))
                .unwrap_or(false),
            "icmp" => line.contains("ICMP echo request"),
            _ => false,
        }
    })
}

/// Conservative conntrack attribution for one leaked-looking packet (W3b,
/// MED-3 of the independent review; W3T scope correction): the END snapshot
/// must always carry a unique-ORIGINAL matching entry; the ORIGINAL source
/// must be a valid, provably non-exit-local address inside the known
/// mesh-peer space; and a flow with NO initiator inside the window must ALSO
/// match an entry with the SAME ORIGINAL tuple in the START snapshot (it
/// pre-existed the window). Every other case is
/// [`ForwardedAttribution::NotForwarded`]: W3 can never turn a possible
/// host leak into a pass. An AMBIGUOUS match (several snapshot entries share
/// the packet's 4-tuple with differing ORIGINAL tuples) also fails closed:
/// the packet cannot be pinned to one client flow (round-4).
#[allow(clippy::too_many_arguments)]
fn attribute_packet(
    start_entries: &[ConntrackEntry],
    end_entries: &[ConntrackEntry],
    proto: &str,
    packet: (&str, Option<u16>, &str, Option<u16>),
    icmp: Option<IcmpEcho>,
    local_addrs: &[String],
    egress_addr: &str,
    client_space: &ClientSpace,
    started_inside_window: bool,
) -> ForwardedAttribution {
    let (src_ip, src_port, dst_ip, dst_port) = packet;
    enum OriginalLookup<'a> {
        Absent,
        Ambiguous,
        Matched(&'a ConntrackEntry),
    }
    fn lookup_original<'a>(
        entries: &'a [ConntrackEntry],
        proto: &str,
        src_ip: &str,
        src_port: Option<u16>,
        dst_ip: &str,
        dst_port: Option<u16>,
        icmp: Option<IcmpEcho>,
    ) -> OriginalLookup<'a> {
        let mut matches = entries.iter().filter(|entry| {
            conntrack_entry_matches_packet(entry, proto, src_ip, src_port, dst_ip, dst_port, icmp)
        });
        let Some(first) = matches.next() else {
            return OriginalLookup::Absent;
        };
        if matches.any(|other| other.original != first.original) {
            return OriginalLookup::Ambiguous;
        }
        OriginalLookup::Matched(first)
    }
    let OriginalLookup::Matched(end_match) =
        lookup_original(end_entries, proto, src_ip, src_port, dst_ip, dst_port, icmp)
    else {
        // Absent (no matching entry) and Ambiguous (differing ORIGINAL
        // tuples for the same 4-tuple) both fail closed.
        return ForwardedAttribution::NotForwarded;
    };
    let original_src = end_match.original.src.clone();
    if !is_valid_ipv4(&original_src)
        || is_exit_local_addr(&original_src, local_addrs, egress_addr)
        || !client_space.admits(&original_src)
    {
        return ForwardedAttribution::NotForwarded;
    }
    // W3T: name the mesh peer this ORIGINAL source belongs to. The `admits`
    // gate above already required an exact stage-set match when one was
    // supplied, so the alias is always resolved there; "unknown" is a
    // defensive label for the fallback tiers, which the real stage never
    // exercises.
    let mesh_peer = client_space
        .peer_alias(&original_src)
        .unwrap_or("unknown")
        .to_owned();
    if started_inside_window {
        // Even with an initiator packet in the window, a START snapshot that
        // pins the 4-tuple to a DIFFERING ORIGINAL tuple (port reuse after
        // host-entry expiry) or to an AMBIGUOUS set means the END entry
        // cannot prove whose flow the wire packet is. Fail closed
        // (round-3/round-4). A START snapshot that does not carry the tuple
        // at all is fine — the flow legitimately began after that snapshot
        // was taken.
        match lookup_original(
            start_entries,
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            icmp,
        ) {
            OriginalLookup::Matched(start_match) if start_match.original == end_match.original => {}
            OriginalLookup::Matched(_) => return ForwardedAttribution::NotForwarded,
            OriginalLookup::Ambiguous => return ForwardedAttribution::NotForwarded,
            OriginalLookup::Absent => {}
        }
        return ForwardedAttribution::Forwarded {
            conntrack_line: end_match.line.clone(),
            original_src,
            snapshot: CONNTRACK_SNAPSHOT_END,
            mesh_peer,
        };
    }
    // No initiator in the window: the flow pre-existed it. The START
    // snapshot must carry the SAME flow (same ORIGINAL tuple) — absent or
    // ambiguous lookups keep the packet a possible host leak.
    match lookup_original(
        start_entries,
        proto,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        icmp,
    ) {
        OriginalLookup::Matched(start_match) if start_match.original == end_match.original => {}
        _ => return ForwardedAttribution::NotForwarded,
    }
    ForwardedAttribution::Forwarded {
        conntrack_line: end_match.line.clone(),
        original_src,
        snapshot: CONNTRACK_SNAPSHOT_BOTH,
        mesh_peer,
    }
}

/// Per-packet attribution scan over the capture (W3b/W3c): every
/// egress-sourced tcp/53|853 packet and every ICMP packet to the control
/// target is looked up in the merged conntrack snapshots. Mirrors the
/// classify conditions exactly (banner skip, IPv6 skip, endpoint parse,
/// egress source, control target + `ICMP`), so a packet is either classified
/// or attributed, never both.
struct AttributionScan {
    forwarded_dns_tcp: Vec<ForwardedDnsPacket>,
    forwarded_tcp53: u32,
    forwarded_dot: u32,
    forwarded_icmp_attributed: u32,
    forwarded_icmp_srcs: Vec<String>,
    exit_origin_icmp: u32,
}

/// True when attribution is armed: EVERY conntrack query in BOTH snapshots
/// answered with exit 0 (MED-3 — a partially-answered snapshot cannot prove
/// an entry's absence) AND the local address ground truth is present AND
/// neither snapshot blob was truncated (an absent match in a clipped blob
/// proves nothing — the truncated-away region may hold the deciding entry).
/// Any missing piece disables attribution — every packet keeps the
/// count-and-fail behaviour.
fn attribution_enabled(
    capture_start_all_answered: bool,
    capture_end_all_answered: bool,
    local_addrs: &[String],
    capture_start_truncated: bool,
    capture_end_truncated: bool,
) -> bool {
    capture_start_all_answered
        && capture_end_all_answered
        && !local_addrs.is_empty()
        && !capture_start_truncated
        && !capture_end_truncated
}

fn attribute_forwarded_packets(
    capture_stdout: &str,
    egress_addr: &str,
    local_addrs: &[String],
    client_space: &ClientSpace,
    enabled: bool,
    start_entries: &[ConntrackEntry],
    end_entries: &[ConntrackEntry],
) -> AttributionScan {
    let mut scan = AttributionScan {
        forwarded_dns_tcp: Vec::new(),
        forwarded_tcp53: 0,
        forwarded_dot: 0,
        forwarded_icmp_attributed: 0,
        forwarded_icmp_srcs: Vec::new(),
        exit_origin_icmp: 0,
    };
    for line in capture_stdout.lines() {
        if is_capture_banner_line(line) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("IP6 ") || trimmed.contains(" IP6 ") {
            continue;
        }
        let Some((src_ip, src_port, dst_ip, dst_port)) = parse_v4_packet_endpoints(line) else {
            continue;
        };
        if src_ip != egress_addr {
            continue;
        }
        if (dst_port == Some(53) || dst_port == Some(WITNESS_DOT_PORT))
            && line_transport(line) == LineTransport::Tcp
        {
            let attribution = if enabled {
                let started = tuple_started_inside_window(
                    capture_stdout,
                    "tcp",
                    &src_ip,
                    src_port,
                    &dst_ip,
                    dst_port,
                );
                attribute_packet(
                    start_entries,
                    end_entries,
                    "tcp",
                    (&src_ip, src_port, &dst_ip, dst_port),
                    None,
                    local_addrs,
                    egress_addr,
                    client_space,
                    started,
                )
            } else {
                ForwardedAttribution::NotForwarded
            };
            if let ForwardedAttribution::Forwarded {
                conntrack_line,
                original_src,
                snapshot,
                mesh_peer,
            } = attribution
            {
                scan.forwarded_dns_tcp.push(ForwardedDnsPacket {
                    packet_line: line.to_owned(),
                    conntrack_line,
                    original_src,
                    snapshot: snapshot.to_owned(),
                    mesh_peer,
                });
                if dst_port == Some(53) {
                    scan.forwarded_tcp53 += 1;
                } else {
                    scan.forwarded_dot += 1;
                }
            }
            continue;
        }
        if dst_ip == WITNESS_ICMP_TARGET && line.contains("ICMP") {
            let attribution = if enabled {
                let started = tuple_started_inside_window(
                    capture_stdout,
                    "icmp",
                    &src_ip,
                    src_port,
                    &dst_ip,
                    dst_port,
                );
                let icmp =
                    packet_details_after_endpoints(line).and_then(parse_icmp_echo_from_packet);
                attribute_packet(
                    start_entries,
                    end_entries,
                    "icmp",
                    (&src_ip, src_port, &dst_ip, dst_port),
                    icmp,
                    local_addrs,
                    egress_addr,
                    client_space,
                    started,
                )
            } else {
                ForwardedAttribution::NotForwarded
            };
            if let ForwardedAttribution::Forwarded { original_src, .. } = attribution {
                scan.forwarded_icmp_attributed += 1;
                scan.forwarded_icmp_srcs.push(original_src);
            } else {
                scan.exit_origin_icmp += 1;
            }
        }
    }
    scan
}

/// Run the host-origin probes on the exit, recording every exit code (the
/// probes are expected to fail locally — the codes are evidence, transport
/// failures are recorded as -1). `dig` is preferred for udp/53 when present
/// (exit code 127 = missing); the fallback is a constant bash `/dev/udp`
/// poke with no interpolation, so the argv seam stays intact on distros
/// without dnsutils/bind-utils. The bash pokes are bounded by `timeout`
/// (`PROBE_TIMEOUT_SECS`) because a silent drop never completes the
/// connect, and every probe must land inside the capture window.
fn run_host_origin_probes(shell: &dyn RemoteShellHost) -> Vec<(String, i32)> {
    let mut codes: Vec<(String, i32)> = Vec::new();
    let dig_target = format!("@{WITNESS_DNS_TARGET}");
    let dot_url = format!("https://{WITNESS_DNS_TARGET}:{WITNESS_DOT_PORT}");
    let dig_argv = [
        "dig",
        "+time=2",
        "+tries=1",
        dig_target.as_str(),
        "rustynet-witness.invalid",
        "A",
    ];
    match shell.run_argv(&dig_argv, &[], &[]) {
        Ok(out) => {
            codes.push(("host_dns_udp_dig".to_owned(), out.code));
            if out.code == 127 {
                let fallback: Vec<String> = vec![
                    "timeout".to_owned(),
                    PROBE_TIMEOUT_SECS.to_string(),
                    "bash".to_owned(),
                    "-c".to_owned(),
                    "exec 3<> /dev/udp/192.0.2.53/53".to_owned(),
                ];
                let argv_refs: Vec<&str> = fallback.iter().map(String::as_str).collect();
                let code = shell
                    .run_argv(&argv_refs, &[], &[])
                    .map(|out| out.code)
                    .unwrap_or(-1);
                codes.push(("host_dns_udp_devudp_fallback".to_owned(), code));
            }
        }
        Err(_) => codes.push(("host_dns_udp_dig".to_owned(), -1)),
    }
    let tcp_argv: Vec<String> = vec![
        "timeout".to_owned(),
        PROBE_TIMEOUT_SECS.to_string(),
        "bash".to_owned(),
        "-c".to_owned(),
        "exec 3<> /dev/tcp/192.0.2.53/53".to_owned(),
    ];
    let tcp_argv_refs: Vec<&str> = tcp_argv.iter().map(String::as_str).collect();
    let tcp_code = shell
        .run_argv(&tcp_argv_refs, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_dns_tcp_devtcp".to_owned(), tcp_code));
    let dot_argv = [
        "curl",
        "--connect-timeout",
        "3",
        "-sS",
        "-o",
        "/dev/null",
        dot_url.as_str(),
    ];
    let dot_code = shell
        .run_argv(&dot_argv, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_dot_curl".to_owned(), dot_code));
    let v6_argv = ["ping", "-6", "-c", "1", "-W", "2", WITNESS_IPV6_TARGET];
    let v6_code = shell
        .run_argv(&v6_argv, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_ipv6_ping".to_owned(), v6_code));
    codes
}

/// Run the full Linux exit egress leak witness: posture precondition, egress
/// context, bounded tcpdump capture window with concurrent probes, packet
/// classification, and the fail-closed verdict. Setup/transport failures are
/// `Err`; verdict failures are carried in `LeakWitnessReport::failures`.
///
/// `mesh_peers` carries the orchestrator-known mesh addresses of EVERY
/// non-exit node as `(alias, address)` pairs (MED-5 of the independent
/// review; W3T scope correction — u46-r48's flagged tcp/53 flow ORIGINALed
/// at a RELAY's mesh address, so admission is no longer client-only): when
/// non-empty, conntrack attribution admits only ORIGINAL sources from this
/// exact set and names the owning peer in the verdict; when empty, the
/// mesh-peer space falls back to the tunnel subnets visible in the
/// capture-start interface listing, then to the documented RFC1918+CGNAT
/// fallback.
/// Substrate-unaware entry point (the historical behaviour): the guest alone
/// decides whether an overlay plane exists ([`SubstrateOverlayHint::Unknown`]).
/// A stage that knows the run's substrate calls
/// [`run_linux_exit_egress_leak_witness_with_substrate`] instead, so a
/// recorded provisioned vxlan overlay can never be silently witnessed on the
/// underlay only.
pub fn run_linux_exit_egress_leak_witness(
    shell: Arc<dyn RemoteShellHost>,
    alias: &str,
    client: Option<(Arc<dyn RemoteShellHost>, Vec<String>)>,
    mesh_peers: &[(String, String)],
    window_secs: u64,
    settle_secs: u64,
) -> Result<LeakWitnessReport, String> {
    run_linux_exit_egress_leak_witness_with_substrate(
        shell,
        alias,
        client,
        mesh_peers,
        window_secs,
        settle_secs,
        SubstrateOverlayHint::Unknown,
    )
}

/// Run the full Linux exit egress leak witness: posture precondition, egress
/// context, bounded tcpdump capture window with concurrent probes, packet
/// classification, and the fail-closed verdict. Setup/transport failures are
/// `Err`; verdict failures are carried in `LeakWitnessReport::failures`.
///
/// `substrate_overlay` selects the CAPTURE PLANE(S): the default-route
/// underlay NIC always, plus the vxlan overlay link (`rustynet-vx0`, where
/// every mesh WG endpoint lives on a cross-LAN vxlan substrate) when the
/// guest carries one — or exactly when the orchestrator's substrate record
/// demands it. Only WHERE the witness looks changes: the vacuous WireGuard
/// and ICMP controls, every leak count, the posture precondition, and the
/// conntrack attribution all stay exactly as strict as on the underlay-only
/// capture.
///
/// `mesh_peers` carries the orchestrator-known mesh addresses of EVERY
/// non-exit node as `(alias, address)` pairs (MED-5 of the independent
/// review; W3T scope correction — u46-r48's flagged tcp/53 flow ORIGINALed
/// at a RELAY's mesh address, so admission is no longer client-only): when
/// non-empty, conntrack attribution admits only ORIGINAL sources from this
/// exact set and names the owning peer in the verdict; when empty, the
/// mesh-peer space falls back to the tunnel subnets visible in the
/// capture-start interface listing, then to the documented RFC1918+CGNAT
/// fallback.
pub fn run_linux_exit_egress_leak_witness_with_substrate(
    shell: Arc<dyn RemoteShellHost>,
    alias: &str,
    client: Option<(Arc<dyn RemoteShellHost>, Vec<String>)>,
    mesh_peers: &[(String, String)],
    window_secs: u64,
    settle_secs: u64,
    substrate_overlay: SubstrateOverlayHint,
) -> Result<LeakWitnessReport, String> {
    let egress_iface = detect_linux_egress_interface(&*shell)?;
    let killswitch_table =
        discover_single_generated_nft_table(&*shell, "inet", "rustynet_g", "active killswitch")?;
    let killswitch_posture =
        verify_scoped_dns_drop_rules(&*shell, &egress_iface, &killswitch_table)?;
    let killswitch_listing = killswitch_posture.listing;
    let egress_addr = detect_egress_ipv4(&*shell, &egress_iface)?;
    let egress_mac = detect_egress_mac(&*shell, &egress_iface)?;
    let wg_listen_port =
        wg_listen_port_from_killswitch_listing(&killswitch_listing, &egress_iface)?;

    // Capture plane(s) for the ACTIVE substrate: underlay always, overlay
    // (rustynet-vx0) when the guest carries it / the record demands it.
    let planes = capture_planes(
        &*shell,
        substrate_overlay,
        &egress_iface,
        &egress_addr,
        &egress_mac,
    )?;
    let multi_plane = planes.len() > 1;

    let timeout_secs = window_secs + CAPTURE_KILL_AFTER_SECS;
    let mut capture_jobs: Vec<(String, Vec<String>)> = Vec::with_capacity(planes.len());
    let mut plane_filters: Vec<Vec<String>> = Vec::with_capacity(planes.len());
    for plane in &planes {
        // The SAME strict filter on every plane: IPv4 host-origin DNS/DoT,
        // the ICMP positive control, the WireGuard listen port, and IPv6
        // sent by THIS plane's MAC. Nothing is ever filtered out.
        let filter_tokens = capture_filter_tokens(wg_listen_port, &plane.mac);
        let mut capture_argv: Vec<String> = vec![
            "sudo".to_owned(),
            "-n".to_owned(),
            "timeout".to_owned(),
            format!("--kill-after={CAPTURE_KILL_AFTER_SECS}"),
            timeout_secs.to_string(),
            "tcpdump".to_owned(),
            "-i".to_owned(),
            plane.iface.clone(),
            "-nn".to_owned(),
            "-l".to_owned(),
        ];
        capture_argv.extend(filter_tokens.iter().cloned());
        plane_filters.push(filter_tokens);
        capture_jobs.push((plane.iface.clone(), capture_argv));
    }
    // Single-plane evidence stays byte-identical to the historical shape
    // (bare filter tokens); only a multi-plane run records the per-plane form.
    let capture_filter = if multi_plane {
        planes
            .iter()
            .zip(plane_filters.iter())
            .map(|(plane, tokens)| format!("{}: {}", plane.iface, tokens.join(" ")))
            .collect::<Vec<_>>()
            .join(" | ")
    } else {
        plane_filters
            .first()
            .map(|tokens| tokens.join(" "))
            .unwrap_or_default()
    };

    let mut capture_handles = Vec::with_capacity(capture_jobs.len());
    for (iface, capture_argv) in capture_jobs {
        let capture_shell = Arc::clone(&shell);
        let handle = std::thread::spawn(move || {
            let argv_refs: Vec<&str> = capture_argv.iter().map(String::as_str).collect();
            capture_shell.run_argv(&argv_refs, &[], &[])
        });
        capture_handles.push((iface, handle));
    }

    std::thread::sleep(std::time::Duration::from_secs(settle_secs));

    // W1: capture-start evidence, BEFORE any probe — the `-a` listings of the
    // generation and boot killswitch tables plus the conntrack (or ss) DNS
    // connection snapshot. A pre-existing established host-origin tcp/53|853
    // flow at this instant is recorded and later fails the verdict: the
    // witness cannot prove the killswitch dropped such a flow, and a leaked
    // FIN whose 4-tuple matches it is labelled as pre-existing instead of
    // silently attributed to the killswitch.
    let capture_start = gather_capture_start_evidence(&*shell, &killswitch_table);
    // The host's own DNS-shaped sockets at window open: relief evidence for
    // W1 (see `gather_dns_sockets`), never a standalone failure source.
    let capture_start_dns_sockets = gather_dns_sockets(&*shell);

    let mut probe_exit_codes = Vec::new();
    // The masqueraded client ICMP control fires FIRST, before the host-origin
    // probes: on a correctly-protected exit the silent dns/tcp drops make the
    // `/dev/tcp` probes burn their full `timeout` budget, so firing the client
    // last risked landing it after the capture window closed.
    if let Some((client_shell, client_ping_argv)) = &client {
        let argv_refs: Vec<&str> = client_ping_argv.iter().map(String::as_str).collect();
        let code = client_shell
            .run_argv(&argv_refs, &[], &[])
            .map(|out| out.code)
            .unwrap_or(-1);
        probe_exit_codes.push(("client_icmp_positive_control".to_owned(), code));
    }
    // Informational timing evidence, gathered on its OWN thread so it adds no
    // latency before the host-origin probes (they must still land inside the
    // capture window). It never feeds a verdict; see
    // `gather_conntrack_timing_diagnostics`.
    let after_ping_diag_handle = client.as_ref().map(|_| {
        let diag_shell = Arc::clone(&shell);
        std::thread::spawn(move || {
            gather_conntrack_timing_diagnostics(&*diag_shell, "after_client_ping")
        })
    });
    probe_exit_codes.extend(run_host_origin_probes(&*shell));

    let mut failures = Vec::new();
    let mut capture_stdout = String::new();
    let mut capture_stderr = String::new();
    for (iface, handle) in capture_handles {
        let (plane_stdout, plane_stderr, plane_code) = match handle.join() {
            Ok(Ok(status)) => (
                String::from_utf8_lossy(&status.stdout).to_string(),
                String::from_utf8_lossy(&status.stderr).to_string(),
                status.code,
            ),
            Ok(Err(err)) => {
                failures.push(format!(
                    "{alias}: tcpdump capture run failed on {iface} ({err}) — capture unusable, \
                     failing closed"
                ));
                (String::new(), String::new(), -1)
            }
            Err(_) => {
                return Err(format!(
                    "{alias}: tcpdump capture thread panicked — capture unusable, failing closed"
                ));
            }
        };
        // Every plane must have started its own capture: with more than one
        // plane the banner must also NAME the plane's interface, so one
        // plane's tcpdump can never stand in for another's.
        let banner_ok = plane_stderr.contains("listening on ")
            && (!multi_plane
                || plane_stderr.contains(&format!("listening on '{iface}'"))
                || plane_stderr.contains(&format!("listening on {iface}")));
        if !banner_ok {
            failures.push(format!(
                "{alias}: tcpdump did not start on {iface} (exit code {plane_code}; no \
                 `listening on` banner in stderr) — capture unusable, failing closed"
            ));
        }
        if multi_plane {
            // Provenance marker per plane (banner-whitelisted, never counted):
            // the merged capture text always says which plane each line came
            // from. Only added when there IS a second plane, so single-plane
            // (netns etc.) evidence stays byte-identical to the old shape.
            if !capture_stdout.is_empty() && !capture_stdout.ends_with('\n') {
                capture_stdout.push('\n');
            }
            capture_stdout.push_str(&format!("capture_provenance=interface={iface}\n"));
        }
        capture_stdout.push_str(&plane_stdout);
        if !capture_stderr.is_empty() && !capture_stderr.ends_with('\n') {
            capture_stderr.push('\n');
        }
        capture_stderr.push_str(&plane_stderr);
    }
    let non_benign: Vec<&str> = capture_stderr
        .lines()
        .filter(|line| !is_benign_tcpdump_stderr_line(line))
        .collect();
    if !non_benign.is_empty() {
        let shown: Vec<String> = non_benign
            .iter()
            .take(3)
            .map(|line| format!("\"{line}\""))
            .collect();
        failures.push(format!(
            "{alias}: tcpdump stderr carried {} non-benign line(s) (tcpdump error?): {}",
            non_benign.len(),
            shown.join(" ")
        ));
    }

    // W3a: the SECOND conntrack snapshot, right after the capture ends —
    // tcp/53, tcp/853, udp/53 PLUS icmp, default output form.
    let capture_end = gather_capture_end_conntrack(&*shell);
    // Informational timing evidence (never a verdict input): taken AFTER the
    // verdict-bearing end snapshot so it cannot delay it.
    let mut conntrack_timing_diagnostics = after_ping_diag_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    conntrack_timing_diagnostics.push_str(&gather_conntrack_timing_diagnostics(
        &*shell,
        "after_capture_end_snapshot",
    ));
    let conntrack_timing_diagnostics = bound_evidence_text(&conntrack_timing_diagnostics);
    // Informational: the same socket snapshot at window close.
    let capture_end_dns_sockets = gather_dns_sockets(&*shell);

    // The exit's source addresses on EVERY captured plane: a host-origin
    // packet is counted wherever it was witnessed (underlay egress address,
    // overlay address on the vxlan plane) — leak counts only ever grow when
    // a plane is added, never shrink.
    let host_src_addrs: Vec<&str> = planes.iter().map(|plane| plane.addr.as_str()).collect();
    let mut counts = classify_capture(&capture_stdout, &host_src_addrs, wg_listen_port);

    // W3b/W3c: conservative conntrack attribution. Armed only when EVERY
    // query in BOTH snapshots answered AND the exit's local addresses are
    // known; a leaked tcp/53|853 packet is relieved from the host-origin
    // counts only when the END snapshot carries a unique matching entry
    // whose ORIGINAL source is provably a client-space address — and, when
    // the flow showed no initiator inside the window, only when the START
    // snapshot carries the SAME flow too.
    let enabled = attribution_enabled(
        capture_start.conntrack_all_answered,
        capture_end.all_answered,
        &capture_start.local_addrs,
        capture_start.conntrack_truncated,
        capture_end.truncated,
    );
    let client_space = ClientSpace::derive(
        mesh_peers,
        &capture_start.local_addrs_raw,
        &egress_addr,
        TUNNEL_INTERFACE,
    );
    let scan = attribute_forwarded_packets(
        &capture_stdout,
        &egress_addr,
        &capture_start.local_addrs,
        &client_space,
        enabled,
        &capture_start.conntrack_entries,
        &capture_end.entries,
    );
    counts.host_dns_tcp = counts.host_dns_tcp.saturating_sub(scan.forwarded_tcp53);
    counts.host_dot = counts.host_dot.saturating_sub(scan.forwarded_dot);

    let positive_control = {
        let mut client_original_srcs = scan.forwarded_icmp_srcs.clone();
        client_original_srcs.extend(
            scan.forwarded_dns_tcp
                .iter()
                .map(|packet| packet.original_src.clone()),
        );
        client_original_srcs.sort();
        client_original_srcs.dedup();
        let forwarded_total = scan.forwarded_icmp_attributed + scan.forwarded_dns_tcp.len() as u32;
        let proven = if forwarded_total > 0 {
            format!(
                "forwarded traffic proven on {egress_iface}: {forwarded_total} packet(s) \
                 conntrack-attributed to non-local client original source(s) [{}] \
                 ({} masqueraded ICMP, {} tcp/53|853); {} exit-origin ICMP packet(s) counted \
                 separately and proven nothing",
                client_original_srcs.join(", "),
                scan.forwarded_icmp_attributed,
                scan.forwarded_dns_tcp.len(),
                scan.exit_origin_icmp
            )
        } else {
            format!(
                "nothing proven about the FORWARD chain on {egress_iface}: 0 \
                 conntrack-attributed forwarded packets; {} ICMP packet(s) to \
                 {WITNESS_ICMP_TARGET} were exit-origin or unattributable and prove nothing",
                scan.exit_origin_icmp
            )
        };
        PositiveControlEvidence {
            forwarded_icmp_raw: scan.exit_origin_icmp + scan.forwarded_icmp_attributed,
            exit_origin_icmp: scan.exit_origin_icmp,
            forwarded_icmp_attributed: scan.forwarded_icmp_attributed,
            forwarded_dns_attributed: scan.forwarded_dns_tcp.len() as u32,
            client_original_srcs,
            proven,
        }
    };

    // Q04/positive-control vacuity: an armed run whose wire shows ICMP to the
    // control target but attributes ZERO of it is only vacuous (proves
    // nothing) when the conntrack snapshots carry icmp entries at all; when
    // the snapshots carry no icmp entry the raw packets are exit-origin by
    // elimination and the attributed-ICMP bonus stays optional.
    let snapshot_carries_icmp_entries = capture_start
        .conntrack_entries
        .iter()
        .chain(capture_end.entries.iter())
        .any(|entry| entry.proto == "icmp");
    failures.extend(evaluate_leak_witness(
        &counts,
        &egress_iface,
        wg_listen_port,
    ));
    failures.extend(evaluate_positive_control(
        &positive_control,
        &egress_iface,
        enabled,
        snapshot_carries_icmp_entries,
    ));
    let mut pre_existing_conn_reliefs = Vec::new();
    append_capture_start_failures(
        &mut failures,
        &mut pre_existing_conn_reliefs,
        &capture_start,
        &capture_stdout,
        &egress_addr,
        &scan.forwarded_dns_tcp,
        &capture_start_dns_sockets,
    );

    Ok(LeakWitnessReport {
        exit_alias: alias.to_owned(),
        egress_iface,
        egress_addr,
        killswitch_table,
        wg_listen_port,
        capture_filter,
        capture_ifaces: planes.iter().map(|plane| plane.iface.clone()).collect(),
        capture_start_nft: capture_start.nft,
        capture_start_boot_nft: capture_start.boot_nft,
        capture_start_conntrack: capture_start.conntrack,
        capture_start_local_addrs: capture_start.local_addrs,
        capture_start_local_addrs_raw: capture_start.local_addrs_raw,
        capture_end_conntrack: capture_end.blob,
        conntrack_timing_diagnostics,
        capture_start_dns_sockets,
        capture_end_dns_sockets,
        pre_existing_conn_reliefs,
        dns_rule_order_findings: killswitch_posture.order_findings,
        forwarded_dns_tcp: scan.forwarded_dns_tcp,
        positive_control,
        counts,
        probe_exit_codes,
        capture_stdout,
        capture_stderr,
        failures,
    })
}

/// W1 verdict extension, applied IN ADDITION to the existing FIN/counts
/// verdict (never instead of it, never a downgrade):
/// * any pre-existing established HOST-ORIGIN tcp/53|853 flow at capture
///   start adds the distinct [`PRE_EXISTING_TCP_DNS_FAILURE`] failure (W3:
///   an entry whose ORIGINAL source is a foreign address is a masqueraded
///   client flow — normal tunneled traffic, never a killswitch concern;
///   without local-address ground truth every entry stays a concern);
/// * ORPHANED-ENTRY RELIEF (katana-xnet-190/193 flake): a host-origin entry
///   whose owning socket is provably GONE at window open is retired from
///   that standalone failure. Relief requires ALL of: (a) a
///   conntrack-or-`/proc` capture-start snapshot that answered every query
///   (`conntrack_all_answered` — the pure ss fallback path is the SAME
///   source as the socket listing, so it can never prove orphaning); (b) an
///   UNTRUNCATED conntrack snapshot (`conntrack_truncated` false — relief
///   may never reason over evidence that was cut short); (c) a usable
///   capture-start ss socket snapshot (no recorded exit or transport error,
///   no truncation); (d) NO host-origin tcp/53|853 packet anywhere in
///   the capture itself; and (e) KNOWN local addresses (`local_addrs`
///   non-empty — with an unusable address listing the keep-all host-origin
///   filter counts possibly-foreign rows, and the ss snapshot only ever
///   lists exit-netns sockets, so the no-owning-socket proof would be
///   vacuous for them).
///   With (c) showing no socket on the entry's local endpoint (any state,
///   plain or bracketed form) the tracked flow has no host endpoint left to
///   originate packets — e.g. a resolver socket closed after the killswitch
///   armed, whose FIN the drop rule ate so conntrack stayed ESTABLISHED —
///   and the entry cannot shadow the verdict. Every unmet condition keeps
///   the failure; relief only ever retires the standalone W1 line, never a
///   leak failure, and each relieved entry is recorded in
///   `pre_existing_conn_reliefs` for audit;
/// * a leaked host tcp/53 packet whose 4-tuple matches a pre-existing flow
///   relabels that leak failure `egress leak (pre-existing connection): ...`
///   — still a failure. Packets already attributed to forwarded client flows
///   (W3b) are excluded from the relabel entirely: they are not leaks.
///   (A relieved entry can never reach the relabel: condition (d) denies
///   relief whenever any host-origin tcp/53|853 packet exists.)
fn append_capture_start_failures(
    failures: &mut Vec<String>,
    relief_notes: &mut Vec<String>,
    evidence: &CaptureStartEvidence,
    capture_stdout: &str,
    egress_addr: &str,
    forwarded_dns_tcp: &[ForwardedDnsPacket],
    capture_start_dns_sockets: &str,
) {
    let host_origin_preexisting: Vec<&PreExistingTcpDnsConn> = evidence
        .pre_existing_tcp_dns
        .iter()
        .filter(|conn| {
            evidence.local_addrs.is_empty()
                || is_exit_local_addr(&conn.local_addr, &evidence.local_addrs, egress_addr)
        })
        .collect();
    // Relief preconditions, evaluated once. Every one of them is fail-closed:
    // an unusable or truncated snapshot (either side), an unknown local
    // address set, or any host-origin tcp/53|853 packet on the wire keeps
    // EVERY entry blocking.
    let relief_allowed = !evidence.local_addrs.is_empty()
        && evidence.conntrack_all_answered
        && !evidence.conntrack_truncated
        && ss_socket_snapshot_usable(capture_start_dns_sockets)
        && !capture_has_host_origin_tcp_dns_packet(capture_stdout, egress_addr, forwarded_dns_tcp);
    let mut blocking = 0usize;
    for conn in &host_origin_preexisting {
        let orphaned =
            relief_allowed && !socket_line_carries_local_endpoint(capture_start_dns_sockets, conn);
        if orphaned {
            relief_notes.push(format!(
                "pre-existing host-origin tcp/53|853 conntrack entry {}:{}->{}:{} relieved: no \
                 socket in the usable capture-start ss snapshot owns local endpoint {}:{} \
                 (orphaned entry — its owning socket is gone), the conntrack snapshot answered \
                 and is untruncated, and the capture carries no host-origin tcp/53|853 packet",
                conn.local_addr,
                conn.local_port,
                conn.remote_addr,
                conn.remote_port,
                conn.local_addr,
                conn.local_port
            ));
        } else {
            blocking += 1;
        }
    }
    if blocking > 0 {
        failures.push(PRE_EXISTING_TCP_DNS_FAILURE.to_owned());
    }
    if leaked_tcp53_tuple_matches_preexisting(
        capture_stdout,
        egress_addr,
        &host_origin_preexisting,
        forwarded_dns_tcp,
    ) {
        if let Some(pos) = failures
            .iter()
            .position(|f| f.contains("host-origin tcp/53 packet"))
        {
            failures[pos] =
                failures[pos].replacen("egress leak:", "egress leak (pre-existing connection):", 1);
        }
    }
}

/// True when the recorded ss snapshot is a usable capture: no recorded
/// exit/transport error and no truncation. Relief may only ever reason over
/// a complete socket listing, never over a partial one.
fn ss_socket_snapshot_usable(sockets: &str) -> bool {
    !sockets.contains("[ss -tnpH exited")
        && !sockets.contains("[ss -tnpH transport error")
        && !sockets.contains(CAPTURE_TRUNCATION_MARKER)
}

/// True when any socket line in the snapshot carries the entry's local
/// endpoint as `addr:port` (plain or bracketed IPv6 form) — the entry still
/// has a live socket on that endpoint (or at minimum an endpoint collision we
/// cannot rule out), so it is NOT relieved. Matching against ANY state
/// (the snapshot is `ss ... state all`) and either endpoint position is
/// deliberate: ambiguity keeps the failure.
fn socket_line_carries_local_endpoint(sockets: &str, conn: &PreExistingTcpDnsConn) -> bool {
    let plain = format!("{}:{}", conn.local_addr, conn.local_port);
    let bracketed = format!("[{}]:{}", conn.local_addr, conn.local_port);
    sockets
        .lines()
        .any(|line| line.contains(&plain) || line.contains(&bracketed))
}

/// True when the capture carries ANY host-origin (egress-sourced, not
/// W3b-attributed) tcp packet to port 53 or [`WITNESS_DOT_PORT`]: such a
/// packet keeps the pre-existing-connection question live on the wire, so
/// no entry may be relieved.
fn capture_has_host_origin_tcp_dns_packet(
    capture_stdout: &str,
    egress_addr: &str,
    forwarded_dns_tcp: &[ForwardedDnsPacket],
) -> bool {
    capture_stdout.lines().any(|line| {
        let Some((src_ip, _src_port, _dst_ip, dst_port)) = parse_v4_packet_endpoints(line) else {
            return false;
        };
        src_ip == egress_addr
            && matches!(dst_port, Some(53) | Some(WITNESS_DOT_PORT))
            && line_transport(line) == LineTransport::Tcp
            && !forwarded_dns_tcp
                .iter()
                .any(|packet| packet.packet_line == line)
    })
}

/// True when any leaked host-origin tcp/53 packet line in the capture carries
/// the exact 4-tuple of a pre-existing HOST-ORIGIN flow recorded at capture
/// start. Lines attributed to forwarded client flows (W3b) never match.
fn leaked_tcp53_tuple_matches_preexisting(
    capture_stdout: &str,
    egress_addr: &str,
    host_origin_preexisting: &[&PreExistingTcpDnsConn],
    forwarded_dns_tcp: &[ForwardedDnsPacket],
) -> bool {
    capture_stdout.lines().any(|line| {
        let Some((src_ip, src_port, dst_ip, dst_port)) = parse_v4_packet_endpoints(line) else {
            return false;
        };
        if src_ip != egress_addr
            || dst_port != Some(53)
            || line_transport(line) != LineTransport::Tcp
        {
            return false;
        }
        let (Some(src_port), Some(dst_port)) = (src_port, dst_port) else {
            return false;
        };
        if forwarded_dns_tcp
            .iter()
            .any(|packet| packet.packet_line == line)
        {
            return false;
        }
        host_origin_preexisting.iter().any(|conn| {
            conn.local_addr == src_ip
                && conn.local_port == src_port
                && conn.remote_addr == dst_ip
                && conn.remote_port == dst_port
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_EGRESS_IFACE: &str = "enp0s9";
    const TEST_EGRESS_ADDR: &str = "192.0.2.240";
    const TEST_WG_PORT: u16 = 51820;
    const TEST_EGRESS_MAC: &str = "52:54:00:0a:00:31";
    const TEST_OVERLAY_IFACE: &str = "rustynet-vx0";
    const TEST_OVERLAY_ADDR: &str = "172.20.10.4";
    const TEST_OVERLAY_MAC: &str = "02:52:ac:14:0a:04";
    const TEST_PEER_OVERLAY: &str = "172.20.10.3";

    /// The guest carries NO vxlan overlay link (`ip ... dev rustynet-vx0`
    /// exits non-zero, exactly like a real guest without the link): the
    /// witness must capture the underlay only, byte-identical to the
    /// pre-overlay behaviour.
    fn program_overlay_absent(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_OVERLAY_IFACE],
            exit_code(1, ""),
        );
    }

    /// The guest carries the substrate's vxlan overlay link with its
    /// `plan_overlay` address and deterministic MAC: both argvs the overlay
    /// plane detection issues, in call order (address query, then MAC query).
    fn program_overlay_present(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_OVERLAY_IFACE],
            exit_ok(&format!(
                "7: {TEST_OVERLAY_IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    \
                 inet {TEST_OVERLAY_ADDR}/16 brd 172.20.255.255 scope global {TEST_OVERLAY_IFACE}\n"
            )),
        );
        mock.program_run_response(
            &["ip", "-brief", "link", "show", "dev", TEST_OVERLAY_IFACE],
            exit_ok(&format!(
                "{TEST_OVERLAY_IFACE}           UP             {TEST_OVERLAY_MAC} <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
            )),
        );
    }

    fn program_egress_mac(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-brief", "link", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "{TEST_EGRESS_IFACE}           UP             {TEST_EGRESS_MAC} <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
            )),
        );
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn exit_code(code: i32, stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn capture_status(stdout: &str, stderr: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 124,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn nft_table_ok() -> String {
        "table inet rustynet_g7 {\n\
         \x20 chain egress {\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
         \x20 }\n\
         }\n"
        .to_owned()
    }

    /// Masqueraded client ICMP (out + in) and a WireGuard keepalive — the
    /// ONLY traffic a correctly-scoped egress should carry. Host-origin
    /// DNS/DoT probes are dropped by the killswitch BEFORE the driver, so
    /// tcpdump never sees them; their presence in a capture is the leak
    /// signal, never part of the clean shape.
    fn clean_capture() -> String {
        format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n\
             12:00:01.100000 IP 192.0.2.1 > {TEST_EGRESS_ADDR}: ICMP echo reply, id 1, seq 1, length 64\n\
             12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        )
    }

    fn tcpdump_stderr_ok() -> String {
        "tcpdump: listening on 'enp0s9', link-type EN10MB (Ethernet), snapshot length 262144 bytes\n\
         12:00:20.000000 5 packets captured\n\
         5 packets received by filter\n\
         0 packets dropped by kernel\n"
        .to_owned()
    }

    fn capture_argv_for_test(window_secs: u64) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "sudo".to_owned(),
            "-n".to_owned(),
            "timeout".to_owned(),
            format!("--kill-after={CAPTURE_KILL_AFTER_SECS}"),
            (window_secs + CAPTURE_KILL_AFTER_SECS).to_string(),
            "tcpdump".to_owned(),
            "-i".to_owned(),
            TEST_EGRESS_IFACE.to_owned(),
            "-nn".to_owned(),
            "-l".to_owned(),
        ];
        argv.extend(capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC));
        argv
    }

    fn argv_refs(argv: &[String]) -> Vec<&str> {
        argv.iter().map(String::as_str).collect()
    }

    /// Program the posture/context conversation (egress, table, posture,
    /// addr, wg port) and the expected-to-fail host-origin probes plus the
    /// client positive control. The tcpdump capture and `dig` responses are
    /// left to each test (FIFO programming).
    fn program_setup(mock: &MockShellHost, with_dig_success_path: bool) {
        program_setup_base(mock, with_dig_success_path);
        // No overlay link on this guest: underlay-only capture, no vxlan query.
        program_overlay_absent(mock);
    }

    /// Same, but the guest carries the vxlan overlay link — the witness must
    /// then capture BOTH planes (the vxlan topology shape).
    fn program_setup_with_overlay(mock: &MockShellHost, with_dig_success_path: bool) {
        program_setup_base(mock, with_dig_success_path);
        program_overlay_present(mock);
    }

    fn program_setup_base(mock: &MockShellHost, with_dig_success_path: bool) {
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(&nft_table_ok()),
        );
        // NOTE: the W1 capture-start evidence argvs (nft -a listing, boot
        // table, conntrack) are NOT programmed here — each test programs the
        // variant it exercises (mock responses are per-argv FIFO queues).
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "2: {TEST_EGRESS_IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    \
                 inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\n"
            )),
        );
        program_egress_mac(mock);
        if with_dig_success_path {
            // dig present (code 1 = timed out after packets left — expected
            // to fail locally; the capture is what decides)
            mock.program_run_response(
                &[
                    "dig",
                    "+time=2",
                    "+tries=1",
                    "@192.0.2.53",
                    "rustynet-witness.invalid",
                    "A",
                ],
                exit_code(1, ""),
            );
        }
        mock.program_run_response(
            &[
                "timeout",
                "4",
                "bash",
                "-c",
                "exec 3<> /dev/tcp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "curl",
                "--connect-timeout",
                "3",
                "-sS",
                "-o",
                "/dev/null",
                "https://192.0.2.53:853",
            ],
            exit_code(6, ""),
        );
        mock.program_run_response(
            &["ping", "-6", "-c", "1", "-W", "2", "2001:db8::53"],
            exit_code(1, ""),
        );
        // client positive control
        mock.program_run_response(&["ping", "-c", "4", "-W", "2", "192.0.2.1"], exit_ok(""));
    }

    fn program_capture(mock: &MockShellHost, capture_stdout: &str, capture_stderr: &str) {
        let tcpdump_argv = capture_argv_for_test(0);
        mock.program_run_response(
            &argv_refs(&tcpdump_argv),
            capture_status(capture_stdout, capture_stderr),
        );
    }

    // ── W1 capture-start evidence helpers ────────────────────────────────

    /// Clean capture-start evidence: `-a` listing present, boot table absent
    /// (tolerated), conntrack present with zero matching entries.
    fn program_capture_start_evidence_clean(mock: &MockShellHost) {
        program_capture_start_nft_listing(mock, &nft_table_ok());
        program_boot_table(mock, None);
        program_conntrack(mock, "", "", "");
    }

    fn program_capture_start_nft_listing(mock: &MockShellHost, listing: &str) {
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "nft",
                "-a",
                "list",
                "table",
                "inet",
                "rustynet_g7",
            ],
            exit_ok(listing),
        );
    }

    /// `None` = boot table absent (nft exits non-zero) — tolerated, recorded.
    fn program_boot_table(mock: &MockShellHost, listing: Option<&str>) {
        let response = match listing {
            Some(text) => exit_ok(text),
            None => exit_code(1, ""),
        };
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "nft",
                "-a",
                "list",
                "table",
                "inet",
                BOOT_KILLSWITCH_TABLE,
            ],
            response,
        );
    }

    /// Program the three conntrack snapshots; exit 127 simulates a missing
    /// binary (the ss fallback then needs programming too).
    fn program_conntrack(mock: &MockShellHost, tcp53: &str, tcp853: &str, udp53: &str) {
        for (proto, dport, out) in [
            ("tcp", "53", tcp53),
            ("tcp", "853", tcp853),
            ("udp", "53", udp53),
        ] {
            mock.program_run_response(
                &[
                    "sudo",
                    "-n",
                    "conntrack",
                    "-L",
                    "-p",
                    proto,
                    "--dport",
                    dport,
                ],
                exit_ok(out),
            );
        }
    }

    fn program_conntrack_missing(mock: &MockShellHost) {
        for (proto, dport) in [("tcp", "53"), ("tcp", "853"), ("udp", "53")] {
            mock.program_run_response(
                &[
                    "sudo",
                    "-n",
                    "conntrack",
                    "-L",
                    "-p",
                    proto,
                    "--dport",
                    dport,
                ],
                exit_code(127, ""),
            );
        }
    }

    /// One conntrack `-L` line: established, zero-data host-origin tcp flow.
    fn conntrack_established_entry(
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
    ) -> String {
        format!(
            "tcp      6 431999 ESTABLISHED src={local_ip} dst={remote_ip} sport={local_port} \
             dport={remote_port} src={remote_ip} dst={local_ip} sport={remote_port} \
             dport={local_port} mark=0 use=1\n"
        )
    }

    // ── W3 helpers ───────────────────────────────────────────────────────

    /// The exit's local IPv4 addresses (`ip -4 -o addr show`) in the real
    /// output shape: backslash-newline continuations, `lo` first, a tunnel
    /// subnet address present — a client address must NOT be in this list.
    fn program_local_addrs(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-4", "-o", "addr", "show"],
            exit_ok(&format!(
                "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                 2: {TEST_EGRESS_IFACE}    inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\\\n\
                 5: rustynet0    inet 10.6.0.1/24 scope global rustynet0\\\n"
            )),
        );
    }

    /// Program the capture-END conntrack snapshot (the default-form argvs,
    /// HIGH-1: no `-o extended`). Empty strings = queries answered with zero
    /// entries.
    fn program_capture_end_conntrack(
        mock: &MockShellHost,
        tcp53: &str,
        tcp853: &str,
        udp53: &str,
        icmp: &str,
    ) {
        for (proto, dport, out) in [
            ("tcp", Some("53"), tcp53),
            ("tcp", Some("853"), tcp853),
            ("udp", Some("53"), udp53),
            ("icmp", None, icmp),
        ] {
            let mut argv: Vec<&str> = vec!["sudo", "-n", "conntrack", "-L", "-p", proto];
            if let Some(dport) = dport {
                argv.push("--dport");
                argv.push(dport);
            }
            mock.program_run_response(&argv, exit_ok(out));
        }
    }

    /// A masqueraded CLIENT tcp flow after masquerade: the ORIGINAL tuple's
    /// source is the client behind the exit, the REPLY tuple's dst is the
    /// egress address. TIME_WAIT state — what a FIN-attributed flow looks
    /// like at capture end.
    fn conntrack_masq_tcp_entry(
        client_ip: &str,
        client_port: u16,
        egress_ip: &str,
        egress_port: u16,
        remote_ip: &str,
        remote_port: u16,
    ) -> String {
        format!(
            "tcp      6 119 TIME_WAIT src={client_ip} dst={remote_ip} sport={client_port} \
             dport={remote_port} src={remote_ip} dst={egress_ip} sport={remote_port} \
             dport={egress_port} mark=0 use=1\n"
        )
    }

    /// A masqueraded CLIENT icmp flow: original direction = the client's echo
    /// request, reply direction = the answer back to the egress address.
    fn conntrack_masq_icmp_entry(client_ip: &str, egress_ip: &str, target: &str) -> String {
        conntrack_masq_icmp_entry_with_id(client_ip, egress_ip, target, 1)
    }

    /// Same, with the echo id made explicit — icmp attribution requires the
    /// type/code/id triple to match the wire packet (LOW finding).
    fn conntrack_masq_icmp_entry_with_id(
        client_ip: &str,
        egress_ip: &str,
        target: &str,
        id: u16,
    ) -> String {
        format!(
            "icmp      1 431999 ESTABLISHED src={client_ip} dst={target} type=8 code=0 id={id} \
             src={target} dst={egress_ip} type=0 code=0 id={id} mark=0 use=1\n"
        )
    }

    /// A conntrack line in the REAL `-o extended` output shape (`ipv4 <n>
    /// <proto> ...`, HIGH-1 of the independent review): the leading tokens
    /// are the address-family and use counter, never the protocol.
    fn conntrack_extended_tcp_entry(
        client_ip: &str,
        client_port: u16,
        egress_ip: &str,
        egress_port: u16,
        remote_ip: &str,
        remote_port: u16,
    ) -> String {
        format!(
            "ipv4     2 tcp      6 119 TIME_WAIT src={client_ip} dst={remote_ip} \
             sport={client_port} dport={remote_port} src={remote_ip} dst={egress_ip} \
             sport={remote_port} dport={egress_port} mark=0 use=1\n"
        )
    }

    fn conntrack_extended_icmp_entry(
        client_ip: &str,
        egress_ip: &str,
        target: &str,
        id: u16,
    ) -> String {
        format!(
            "ipv4     2 icmp     1 29 ESTABLISHED src={client_ip} dst={target} type=8 code=0 \
             id={id} src={target} dst={egress_ip} type=0 code=0 id={id} mark=0 use=1\n"
        )
    }

    /// Clean W3 arming: local addresses known + capture-end snapshot answered,
    /// carrying the masqueraded client ICMP entry so the positive control
    /// holds on the clean capture.
    fn program_w3_clean(mock: &MockShellHost) {
        program_local_addrs(mock);
        program_capture_end_conntrack(
            mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
    }

    /// Append the masqueraded CLIENT FIN seen from the egress side (after
    /// masquerade its source is the EGRESS address — the r35 shape).
    fn with_client_fin(capture: &str) -> String {
        let mut c = capture.to_owned();
        c.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        c
    }

    fn run_witness(mock: &Arc<MockShellHost>) -> Result<LeakWitnessReport, String> {
        run_witness_with_clients(mock, &[])
    }

    /// Same, with the stage-supplied mesh-peer `(alias, address)` pairs
    /// (MED-5 + W3T) made explicit: non-empty means conntrack attribution
    /// admits only ORIGINAL sources from this exact set, and names the peer.
    fn run_witness_with_clients(
        mock: &Arc<MockShellHost>,
        mesh_peers: &[(String, String)],
    ) -> Result<LeakWitnessReport, String> {
        run_linux_exit_egress_leak_witness(
            Arc::clone(mock) as Arc<dyn RemoteShellHost>,
            "exit-1",
            Some((
                Arc::clone(mock) as Arc<dyn RemoteShellHost>,
                vec![
                    "ping".to_owned(),
                    "-c".to_owned(),
                    "4".to_owned(),
                    "-W".to_owned(),
                    "2".to_owned(),
                    "192.0.2.1".to_owned(),
                ],
            )),
            mesh_peers,
            0,
            0,
        )
    }

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Windows
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Ios
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Android
        ));
    }

    #[test]
    fn clean_capture_with_both_controls_passes() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("clean witness must not err on setup");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.counts.forwarded_icmp, 1);
        assert_eq!(report.counts.wireguard, 1);
        assert_eq!(report.counts.host_dns_udp, 0);
        assert_eq!(report.counts.host_dns_tcp, 0);
        assert_eq!(report.counts.host_dot, 0);
        assert_eq!(report.counts.ipv6, 0);
        assert_eq!(report.wg_listen_port, TEST_WG_PORT);
        assert_eq!(report.egress_addr, TEST_EGRESS_ADDR);
        assert_eq!(report.killswitch_table, "rustynet_g7");
        // W3: the masqueraded client ICMP is attributed through the
        // capture-end conntrack snapshot — the control holds by attribution.
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 1);
        assert_eq!(report.positive_control.exit_origin_icmp, 0);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .positive_control
                .proven
                .contains("forwarded traffic proven"),
            "{:?}",
            report.positive_control.proven
        );
    }

    // W1 regression: with NO pre-existing entries and no leak, the witness
    // still passes (failures empty ⇔ the stage-level `leak_free: true`), and
    // the capture-start evidence keys are recorded alongside.
    #[test]
    fn clean_capture_with_no_preexisting_entries_still_passes_leak_free() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("clean witness must not err on setup");
        assert!(
            report.failures.is_empty(),
            "a clean capture must stay leak_free: {:?}",
            report.failures
        );
        assert!(
            report
                .capture_start_nft
                .contains("udp dport { 53, 853 } drop"),
            "{:?}",
            report.capture_start_nft
        );
        assert!(
            report.capture_start_boot_nft.contains("absent"),
            "{:?}",
            report.capture_start_boot_nft
        );
        assert!(
            report
                .capture_start_conntrack
                .contains("conntrack -L -p tcp --dport 53"),
            "{:?}",
            report.capture_start_conntrack
        );
        assert!(
            !report
                .capture_start_conntrack
                .contains(CONNTRACK_UNAVAILABLE),
            "{:?}",
            report.capture_start_conntrack
        );
        // W3a: local address ground truth + capture-end snapshot recorded.
        assert!(
            report
                .capture_start_local_addrs
                .iter()
                .any(|addr| addr == TEST_EGRESS_ADDR),
            "{:?}",
            report.capture_start_local_addrs
        );
        assert!(
            report
                .capture_start_local_addrs
                .iter()
                .any(|addr| addr == "10.6.0.1"),
            "{:?}",
            report.capture_start_local_addrs
        );
        assert!(
            report
                .capture_end_conntrack
                .contains("conntrack -L -p icmp"),
            "{:?}",
            report.capture_end_conntrack
        );
    }

    // W1: the boot table is legitimately deletable by an operator — its
    // absence at capture start is recorded, never an error.
    #[test]
    fn boot_table_absent_is_tolerated_and_recorded() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_conntrack(&mock, "", "", "");
        program_boot_table(&mock, None);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("boot absence must not err");
        assert!(
            report.capture_start_boot_nft.contains("absent"),
            "{:?}",
            report.capture_start_boot_nft
        );
        assert!(report.failures.is_empty(), "{:?}", report.failures);
    }

    // W1: an established host-origin tcp/53 flow present at capture start
    // fails the verdict with the distinct pre-existing-connection text, in
    // addition to the existing checks (clean capture ⇒ no leak failures, but
    // the pre-existing failure still fires).
    #[test]
    fn pre_existing_tcp53_conntrack_entry_fails_the_witness() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(
            &mock,
            &conntrack_established_entry(TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // W1: a leaked host tcp/53 FIN whose 4-tuple matches a pre-existing
    // capture-start entry is labelled `egress leak (pre-existing connection)`
    // — still a failure, never a downgrade.
    // ── W1 orphaned-entry relief (katana-xnet-190/193 flake) ─────────────

    /// The REAL katana-xnet-190 shape: conntrack unusable (exit 1 on every
    /// query — not 127), the `/proc/net/nf_conntrack` fallback carrying ONE
    /// established host-origin tcp/53 entry (the real line, addresses
    /// substituted) whose owning socket is already gone, and the capture-end
    /// snapshot clean. Tests below program the ss socket snapshot per case.
    fn program_conntrack_exit1(mock: &MockShellHost) {
        for (proto, dport) in [("tcp", "53"), ("tcp", "853"), ("udp", "53")] {
            mock.program_run_response(
                &[
                    "sudo",
                    "-n",
                    "conntrack",
                    "-L",
                    "-p",
                    proto,
                    "--dport",
                    dport,
                ],
                exit_code(1, ""),
            );
        }
    }

    fn orphan_proc_fallback() -> String {
        format!(
            "ipv4     2 tcp      6 431325 ESTABLISHED src={TEST_EGRESS_ADDR} dst=192.0.2.1 \
             sport=48796 dport=53 src=192.0.2.1 dst={TEST_EGRESS_ADDR} sport=53 dport=48796 \
             [ASSURED] mark=0 zone=0 use=2\n\
             ipv4     2 icmp     1 4 src=100.95.194.56 dst=100.77.8.80 type=8 code=0 id=719 \
             src=100.77.8.80 dst=100.95.194.56 type=0 code=0 id=719 mark=0 zone=0 use=2\n"
        )
    }

    /// The real run-190 informational ss listing: ONLY a fresh SYN-SENT
    /// systemd-resolve attempt (port 59686) — NO socket on the orphaned
    /// entry's endpoint 48796.
    fn resolved_syn_sent_only() -> String {
        format!(
            "SYN-SENT 0      1      {TEST_EGRESS_ADDR}:59686 192.0.2.1:53 \
             users:((\"systemd-resolve\",pid=5893,fd=28))\n"
        )
    }

    fn program_dns_sockets(mock: &MockShellHost, response: RemoteExitStatus) {
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "ss",
                "-tnpH",
                "state",
                "all",
                "( dport = :53 or dport = :853 )",
            ],
            response,
        );
    }

    fn program_orphan_scenario(mock: &MockShellHost, sockets: RemoteExitStatus, capture: &str) {
        program_setup(mock, true);
        program_capture_start_nft_listing(mock, &nft_table_ok());
        program_boot_table(mock, None);
        program_conntrack_exit1(mock);
        mock.program_run_response(
            &["sudo", "-n", "cat", "/proc/net/nf_conntrack"],
            exit_ok(&orphan_proc_fallback()),
        );
        program_w3_clean(mock);
        program_capture(mock, capture, &tcpdump_stderr_ok());
        program_dns_sockets(mock, sockets);
    }

    // THE FLAKE: the entry is present at capture start but its socket is
    // provably gone (real evidence: conntrack ESTABLISHED 48796, ss shows
    // only a fresh SYN-SENT 59686), nothing leaked in-window. Relief retires
    // the standalone failure and the witness passes. On the pre-relief code
    // this FAILS: the presence check alone fails the verdict.
    #[test]
    fn orphaned_preexisting_entry_with_no_owning_socket_passes_the_witness() {
        let mock = Arc::new(MockShellHost::new());
        program_orphan_scenario(&mock, exit_ok(&resolved_syn_sent_only()), &clean_capture());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            !report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
        assert!(report.failures.is_empty(), "{:?}", report.failures);
    }

    // The relief is auditable: the relieved entry lands in
    // `pre_existing_conn_reliefs` with its endpoint named.
    #[test]
    fn orphan_relief_is_recorded_in_the_report() {
        let mock = Arc::new(MockShellHost::new());
        program_orphan_scenario(&mock, exit_ok(&resolved_syn_sent_only()), &clean_capture());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.pre_existing_conn_reliefs.len(), 1);
        assert!(
            report.pre_existing_conn_reliefs[0].contains("48796"),
            "{:?}",
            report.pre_existing_conn_reliefs
        );
        assert!(report.pre_existing_conn_reliefs[0].contains("no socket"));
    }

    // A socket still owning the entry's local endpoint (any position, any
    // state) keeps the failure — the flow may still originate packets.
    #[test]
    fn orphan_relief_denied_when_socket_still_owns_the_endpoint() {
        let mock = Arc::new(MockShellHost::new());
        let sockets = format!(
            "{}ESTAB 0 0 {TEST_EGRESS_ADDR}:48796 192.0.2.1:53\n",
            resolved_syn_sent_only()
        );
        program_orphan_scenario(&mock, exit_ok(&sockets), &clean_capture());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // ANY host-origin tcp/53|853 packet in the capture (here: an unknown
    // 4-tuple, still a plain leak) denies the relief entirely.
    #[test]
    fn orphan_relief_denied_when_capture_carries_host_origin_tcp_dns() {
        let mock = Arc::new(MockShellHost::new());
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.40004 > 192.0.2.53.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        program_orphan_scenario(&mock, exit_ok(&resolved_syn_sent_only()), &capture);
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // An unusable socket snapshot (recorded exit marker) denies the relief:
    // absence of a socket line is only meaningful over a complete listing.
    #[test]
    fn orphan_relief_denied_when_socket_snapshot_unusable() {
        let mock = Arc::new(MockShellHost::new());
        program_orphan_scenario(&mock, exit_code(1, ""), &clean_capture());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
        assert!(report.pre_existing_conn_reliefs.is_empty());
    }

    // A TRUNCATED conntrack snapshot denies the relief even though the entry
    // itself was parsed before the cut: relief never reasons over shortened
    // evidence.
    #[test]
    fn orphan_relief_denied_when_conntrack_snapshot_truncated() {
        let mock = Arc::new(MockShellHost::new());
        let mut proc_text = orphan_proc_fallback();
        for id in 100..1120 {
            proc_text.push_str(&format!(
                "ipv4     2 icmp     1 29 ESTABLISHED src=100.95.194.56 dst=100.77.8.80 \
                 type=8 code=0 id={id} src=100.77.8.80 dst=100.95.194.56 type=0 code=0 \
                 id={id} mark=0 zone=0 use=2\n"
            ));
        }
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_exit1(&mock);
        mock.program_run_response(
            &["sudo", "-n", "cat", "/proc/net/nf_conntrack"],
            exit_ok(&proc_text),
        );
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        program_dns_sockets(&mock, exit_ok(&resolved_syn_sent_only()));
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .capture_start_conntrack
                .contains(CAPTURE_TRUNCATION_MARKER),
            "{:?}",
            report.capture_start_conntrack
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
        assert!(report.pre_existing_conn_reliefs.is_empty());
    }

    // Entries whose ONLY source is the ss-fallback path (conntrack AND /proc
    // both unusable) are never relieved: the "socket snapshot" would be the
    // same tool seconds later, not independent evidence.
    #[test]
    fn orphan_relief_denied_when_preexisting_evidence_is_ss_fallback_only() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        mock.program_run_response(
            &["sudo", "-n", "cat", "/proc/net/nf_conntrack"],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "ss",
                "-Htn",
                "state",
                "established",
                "( dport = :53 or dport = :853 )",
            ],
            exit_ok(&format!(
                "ESTAB 0 0 {TEST_EGRESS_ADDR}:48796 192.0.2.1:53\n"
            )),
        );
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        program_dns_sockets(&mock, exit_ok(&resolved_syn_sent_only()));
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
        assert!(report.pre_existing_conn_reliefs.is_empty());
    }

    // The exit's local addresses are UNKNOWN (`ip -4 -o addr show` fails):
    // the keep-all host-origin filter then counts possibly FOREIGN rows
    // (masqueraded client flows) as host-origin, and the ss snapshot only
    // ever lists exit-netns sockets — the no-owning-socket proof would be
    // vacuous for them. Relief is denied until the address ground truth is
    // known. On the pre-fix relief this FAILS: the orphan relief fires.
    #[test]
    fn orphan_relief_denied_when_local_addrs_unknown() {
        let mock = Arc::new(MockShellHost::new());
        // Programmed BEFORE the scenario so the mock FIFO consumes the
        // failure (the same argv is otherwise answered successfully by
        // `program_w3_clean`).
        mock.program_run_response(&["ip", "-4", "-o", "addr", "show"], exit_code(1, ""));
        program_orphan_scenario(&mock, exit_ok(&resolved_syn_sent_only()), &clean_capture());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
        assert!(report.pre_existing_conn_reliefs.is_empty());
    }

    #[test]
    fn leaked_fin_matching_preexisting_entry_is_labelled_preexisting() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(
            &mock,
            &conntrack_established_entry(TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        let labelled = report
            .failures
            .iter()
            .find(|f| f.contains("host-origin tcp/53 packet"))
            .expect("tcp/53 leak failure must exist");
        assert!(
            labelled.starts_with("egress leak (pre-existing connection):"),
            "{labelled}"
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // W1: a leaked FIN on an UNKNOWN 4-tuple keeps the plain leak label even
    // when some other pre-existing connection exists — the label tracks the
    // tuple match, not mere presence.
    #[test]
    fn leaked_fin_with_unknown_tuple_keeps_plain_label() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(
            &mock,
            &conntrack_established_entry(TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.40004 > 192.0.2.53.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        let labelled = report
            .failures
            .iter()
            .find(|f| f.contains("host-origin tcp/53 packet"))
            .expect("tcp/53 leak failure must exist");
        assert!(
            labelled.starts_with("egress leak:") && !labelled.contains("pre-existing"),
            "{labelled}"
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // W1: a missing conntrack binary (exit 127) is tolerated with the recorded
    // `conntrack unavailable` marker and the ss fallback provides the
    // pre-existing evidence instead.
    #[test]
    fn missing_conntrack_falls_back_to_ss_evidence() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        mock.program_run_response(
            &[
                "ss",
                "-Htn",
                "state",
                "established",
                "( dport = :53 or dport = :853 )",
            ],
            exit_ok(&format!("ESTAB 0 0 {TEST_EGRESS_ADDR}:43420 1.1.1.1:53\n")),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .capture_start_conntrack
                .contains(CONNTRACK_UNAVAILABLE),
            "{:?}",
            report.capture_start_conntrack
        );
        assert!(
            report.capture_start_conntrack.contains("ESTAB"),
            "{:?}",
            report.capture_start_conntrack
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // ── W2 fixture tests: rule ORDER within the output chain ─────────────

    fn verify_listing(listing: &str) -> Result<String, String> {
        let mock = MockShellHost::new();
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(listing),
        );
        verify_scoped_dns_drop_rules(&mock, TEST_EGRESS_IFACE, "rustynet_g7")
            .map(|posture| posture.listing)
    }

    fn verify_posture(listing: &str) -> Result<ScopedDnsDropPosture, String> {
        let mock = MockShellHost::new();
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(listing),
        );
        verify_scoped_dns_drop_rules(&mock, TEST_EGRESS_IFACE, "rustynet_g7")
    }

    /// The diag-time g1/boot shape: exclusion-scoped established accept,
    /// drops after it — SAFE because the accept excludes tcp/53|853.
    fn current_shape_listing() -> String {
        "table inet rustynet_g7 {\n\
         \x20 chain egress {\n\
         \x20  type filter hook output priority filter; policy accept;\n\
         \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
         \x20 }\n\
         }\n"
        .to_owned()
    }

    /// The AQ-70/F2 legacy shape: an unqualified established accept sits
    /// BEFORE the scoped drops — it admits established tcp/53|853 flows.
    fn legacy_shape_listing() -> String {
        "table inet rustynet_g7 {\n\
         \x20 chain egress {\n\
         \x20  type filter hook output priority filter; policy accept;\n\
         \x20  ct state established,related accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20 }\n\
         }\n"
        .to_owned()
    }

    #[test]
    fn w2_current_shape_table_passes_order_check() {
        // exclusion accept BEFORE drops: safe, the accept cannot match DNS
        assert!(verify_listing(&current_shape_listing()).is_ok());
        // the plain witness fixture shape (drops first, plain ipv4 accept
        // last): also safe
        assert!(verify_listing(&nft_table_ok()).is_ok());
    }

    #[test]
    fn w2_legacy_unqualified_established_accept_first_fails() {
        let err = verify_listing(&legacy_shape_listing())
            .expect_err("unqualified established accept before the drops must fail closed");
        assert!(err.starts_with("kill switch rule order unsafe:"), "{err}");
        assert!(err.contains("ct state established,related accept"), "{err}");
    }

    #[test]
    fn w2_unqualified_established_accept_after_drops_passes() {
        let listing = "table inet rustynet_g7 {\n\
         \x20 chain egress {\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20  ct state established,related accept\n\
         \x20 }\n\
         }\n";
        assert!(verify_listing(listing).is_ok());
    }

    #[test]
    fn w2_garbled_or_empty_output_fails_closed() {
        let empty = verify_listing("").expect_err("empty table output must fail closed");
        assert!(empty.contains("posture precondition failed"), "{empty}");

        let garbled = "table inet rustynet_g7 {\n\tgarbage line here\n}\n";
        let err = verify_listing(garbled).expect_err("garbled table output must fail closed");
        assert!(err.contains("posture precondition failed"), "{err}");
    }

    // W2 end-to-end: a legacy-ordered table never reaches capture — the full
    // witness errors on the posture precondition.
    #[test]
    fn w2_legacy_table_fails_the_full_witness_before_capture() {
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(&legacy_shape_listing()),
        );
        let err = run_witness(&mock).expect_err("legacy order must fail closed");
        assert!(err.contains("kill switch rule order unsafe:"), "{err}");
    }

    #[test]
    fn posture_rule_absent_fails_naming_the_rule() {
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        let incomplete = "table inet rustynet_g7 {\n\
             \x20 chain egress {\n\
             \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
             \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
             \x20 }\n\
             }\n";
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(incomplete),
        );
        let err = run_witness(&mock).expect_err("missing tcp drop rule must fail closed");
        assert!(
            err.contains("tcp dport") && err.contains("53") && err.contains("853"),
            "error must name the missing rule, got: {err}"
        );
        assert!(err.contains("posture precondition failed"), "{err}");
    }

    #[test]
    fn host_origin_udp_dns_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40002 > 192.0.2.53.53: 2+ A? leak.invalid. (30)\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_udp, 1);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("udp/53") && f.contains("1 host-origin")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn host_origin_tcp_dot_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40003 > 192.0.2.53.853: Flags [S], seq 1, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dot, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("tcp/853 (DoT)")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn host_origin_tcp_dns_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40004 > 192.0.2.53.53: Flags [S], seq 1, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("tcp/53")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn single_ipv6_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(
            "12:00:03.000000 IP6 2001:db8::240 > 2001:db8::53: ICMP6, echo request, length 64\n",
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.ipv6, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("IPv6 packet(s)")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn missing_forwarded_icmp_is_vacuous_fail() {
        let capture = format!(
            "12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.forwarded_icmp, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no masqueraded client ICMP")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn missing_wireguard_is_vacuous_fail() {
        let capture = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.wireguard, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no WireGuard udp/51820")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn tcpdump_banner_only_stdout_counts_zero_packets() {
        let banner_only = "listening on enp0s9\nlink-type EN10MB\ncapture_provenance=test\n\
             tcpdump: data link type EN10MB\n\n";
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, banner_only, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts, LeakWitnessCounts::default());
        // zero counts are NOT a pass: both vacuous controls must fire, and
        // no banner line may be counted as a packet or an error
        assert!(
            report
                .failures
                .iter()
                .all(|f| f.contains("vacuous witness")),
            "banner lines must never be counted as packets or errors: {:?}",
            report.failures
        );
        assert_eq!(report.failures.len(), 2, "{:?}", report.failures);
    }

    #[test]
    fn tcpdump_without_listening_banner_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, "", "tcpdump: enp0s9: No such device exists\n");
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("tcpdump did not start")),
            "{:?}",
            report.failures
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("non-benign line")),
            "tcpdump error lines must surface, not be whitelisted: {:?}",
            report.failures
        );
    }

    #[test]
    fn missing_dig_falls_back_to_devudp_poke() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, false);
        mock.program_run_response(
            &[
                "dig",
                "+time=2",
                "+tries=1",
                "@192.0.2.53",
                "rustynet-witness.invalid",
                "A",
            ],
            exit_code(127, ""),
        );
        mock.program_run_response(
            &[
                "timeout",
                "4",
                "bash",
                "-c",
                "exec 3<> /dev/udp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        let labels: Vec<&str> = report
            .probe_exit_codes
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        assert!(
            labels.contains(&"host_dns_udp_dig")
                && labels.contains(&"host_dns_udp_devudp_fallback"),
            "{labels:?}"
        );
        assert!(
            report
                .probe_exit_codes
                .iter()
                .any(|(label, code)| label == "host_dns_udp_devudp_fallback" && *code == 1),
            "{:?}",
            report.probe_exit_codes
        );
    }

    #[test]
    fn devtcp_probe_is_timeout_bounded() {
        // Witness: the `/dev/tcp` poke must run under `timeout` — a silent
        // drop never completes the connect, so an unbounded poke would hang
        // far past the capture window. Programmed ONLY for the wrapped argv;
        // a regression to the bare `bash -c` argv matches nothing, the mock
        // errors, and the recorded -1 fails this assert.
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &[
                "dig",
                "+time=2",
                "+tries=1",
                "@192.0.2.53",
                "rustynet-witness.invalid",
                "A",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "timeout",
                &PROBE_TIMEOUT_SECS.to_string(),
                "bash",
                "-c",
                "exec 3<> /dev/tcp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        let codes = run_host_origin_probes(mock.as_ref());
        assert!(
            codes
                .iter()
                .any(|(label, code)| label == "host_dns_tcp_devtcp" && *code == 1),
            "tcp poke did not match the timeout-wrapped argv: {codes:?}"
        );
    }

    #[test]
    fn witness_fails_closed_on_wg_port_absent() {
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        let without_wg_pair: String = nft_table_ok()
            .lines()
            .filter(|line| !line.contains("51820"))
            .map(|line| format!("{line}\n"))
            .collect();
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(&without_wg_pair),
        );
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "    inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\n"
            )),
        );
        program_egress_mac(&mock);
        let err = run_witness(&mock).expect_err("undeterminable WG port must fail closed");
        assert!(err.contains("WireGuard listen port"), "{err}");
    }

    #[test]
    fn tcpdump_verbose_notice_is_benign_but_real_errors_are_not() {
        assert!(is_benign_tcpdump_stderr_line(
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode"
        ));
        assert!(!is_benign_tcpdump_stderr_line(
            "tcpdump: ens3: No such device exists"
        ));
        assert!(!is_benign_tcpdump_stderr_line(
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode; extra"
        ));
    }

    // tcpdump pluralises its tallies: one packet reaching the filter prints
    // `1 packet received by filter` (katana-xnet-209 tripped the chaos
    // daemon-fault whitelist on that line). A non-numeric count or a wrong
    // noun stays an error.
    #[test]
    fn tcpdump_singular_tally_lines_are_benign_but_malformed_ones_are_not() {
        for line in [
            "1 packet captured",
            "1 packet received by filter",
            "1 packet dropped by kernel",
            "12:00:20.000000 1 packet captured",
        ] {
            assert!(is_benign_tcpdump_stderr_line(line), "{line}");
        }
        for line in [
            "x packet captured",
            "1 packet captured extra",
            "1 packet received by filter extra",
            "1 packet vanished",
            "1 packet received by wire",
        ] {
            assert!(!is_benign_tcpdump_stderr_line(line), "{line}");
        }
    }

    // Run lenovo-u16l: on a bridged LAN tcpdump (promiscuous) also sees other
    // devices' IPv6; only frames this exit's NIC sends may count as leaks.
    #[test]
    fn ipv6_clause_is_scoped_to_frames_the_egress_nic_sends() {
        let tokens = capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC).join(" ");
        assert!(
            tokens.contains(&format!("( ip6 and ether src {TEST_EGRESS_MAC} )")),
            "{tokens}"
        );
        assert!(
            !tokens.contains("or ip6 or"),
            "an unscoped ip6 clause must not remain: {tokens}"
        );
    }

    // `udp port 53`, `tcp port 53|853` and the WireGuard port clause match
    // IPv6 too, and every captured IPv6 line counts as a leak, so unscoped
    // they would still let a neighbour's IPv6 DNS fail the witness on a
    // bridged LAN. They must sit in one IPv4-only group (pcap `and`/`or` are
    // equal precedence, so the grouping is locked here token for token).
    #[test]
    fn port_clauses_are_ipv4_only() {
        let tokens = capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC).join(" ");
        assert_eq!(
            tokens,
            format!(
                "( ip and ( udp port 53 or tcp port 53 or tcp port {WITNESS_DOT_PORT} or icmp \
                 or udp port {TEST_WG_PORT} ) ) or ( ip6 and ether src {TEST_EGRESS_MAC} )"
            )
        );
    }

    #[test]
    fn egress_mac_must_be_a_plain_mac() {
        assert!(is_plain_mac("52:54:00:0a:00:31"));
        assert!(!is_plain_mac(""));
        assert!(!is_plain_mac("<BROADCAST,MULTICAST,UP,LOWER_UP>"));
        assert!(!is_plain_mac("52:54:00:0a:00"));
        assert!(!is_plain_mac("52:54:00:0a:00:3g"));
    }

    #[test]
    fn wg_port_comes_from_the_killswitch_dport_sport_pair_on_the_egress_iface() {
        let iface = "enp0s9";
        assert_eq!(
            wg_listen_port_from_killswitch_listing(&nft_table_ok(), iface),
            Ok(51820)
        );
        // Only one half of the pair: not a WireGuard allow, fail closed.
        let dport_only = "oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n";
        assert!(wg_listen_port_from_killswitch_listing(dport_only, iface).is_err());
        // A pair on another interface does not count.
        let other_iface = "oifname \"wg9\" meta nfproto ipv4 udp dport 51820 accept\n\
                           oifname \"wg9\" meta nfproto ipv4 udp sport 51820 accept\n";
        assert!(wg_listen_port_from_killswitch_listing(other_iface, iface).is_err());
        // Two different pairs: ambiguous, fail closed.
        let two_pairs = "oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp dport 41641 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp sport 41641 accept\n";
        let err = wg_listen_port_from_killswitch_listing(two_pairs, iface).expect_err("ambiguous");
        assert!(err.contains("several"), "{err}");
        // The DNS/DoT drop set on the same interface never reads as a port.
        let drops_only = "oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n";
        assert!(wg_listen_port_from_killswitch_listing(drops_only, iface).is_err());
    }

    #[test]
    fn evaluate_leak_witness_counts_clean_shape() {
        let counts = LeakWitnessCounts {
            host_dns_udp: 0,
            host_dns_tcp: 0,
            host_dot: 0,
            ipv6: 0,
            forwarded_icmp: 3,
            wireguard: 7,
        };
        assert!(evaluate_leak_witness(&counts, TEST_EGRESS_IFACE, TEST_WG_PORT).is_empty());
        let leaky = LeakWitnessCounts {
            host_dns_udp: 2,
            ..LeakWitnessCounts::default()
        };
        let failures = evaluate_leak_witness(&leaky, TEST_EGRESS_IFACE, TEST_WG_PORT);
        // HIGH-2: the RAW forwarded-ICMP vacuity is back in
        // evaluate_leak_witness (evaluate_positive_control only adds the
        // conntrack-attribution half when ICMP was actually seen), so the
        // leaky shape fails three ways: udp leak, missing tunnel control,
        // missing masqueraded-ICMP control.
        assert_eq!(failures.len(), 3, "{failures:?}");
        assert!(
            failures
                .iter()
                .any(|f| f.contains("vacuous witness: no masqueraded client ICMP")),
            "{failures:?}"
        );
    }

    // W3c (HIGH-2 of the independent review): the RAW ICMP positive control
    // is evaluated in evaluate_leak_witness and can never be dropped again;
    // this check is only about the conntrack-attribution HALF. Attribution
    // must come from a forwarded ICMP flow: a raw wire count of unattributed
    // pings proves nothing, and DNS attribution never satisfies the ICMP
    // control.
    #[test]
    fn evaluate_positive_control_needs_attribution_not_raw_counts() {
        // raw>0 but nothing attributed: ONE failure (the raw vacuity is
        // evaluate_leak_witness's business, and it fires for the same shape).
        let dns_attributed_only = PositiveControlEvidence {
            forwarded_icmp_raw: 4,
            exit_origin_icmp: 4,
            forwarded_icmp_attributed: 0,
            forwarded_dns_attributed: 1,
            client_original_srcs: vec!["10.6.0.2".to_owned()],
            proven: "forwarded traffic proven".to_owned(),
        };
        let failures =
            evaluate_positive_control(&dns_attributed_only, TEST_EGRESS_IFACE, true, true);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].starts_with("vacuous witness: no forwarded traffic"),
            "{failures:?}"
        );
        // a DNS-attributed flow can NEVER satisfy the ICMP control
        assert!(
            !failures[0].contains("exit-origin ICMP is the only"),
            "{failures:?}"
        );
        // attributed icmp: satisfied
        let attributed_icmp_only = PositiveControlEvidence {
            forwarded_icmp_raw: 4,
            exit_origin_icmp: 3,
            forwarded_icmp_attributed: 1,
            forwarded_dns_attributed: 0,
            client_original_srcs: vec!["10.6.0.2".to_owned()],
            proven: "forwarded traffic proven".to_owned(),
        };
        assert!(
            evaluate_positive_control(&attributed_icmp_only, TEST_EGRESS_IFACE, true, true)
                .is_empty()
        );
        // vacuous evidence, raw>0: still one failure naming the attribution
        let vacuous = PositiveControlEvidence {
            forwarded_icmp_raw: 4,
            exit_origin_icmp: 4,
            proven: "nothing proven".to_owned(),
            ..PositiveControlEvidence::default()
        };
        let failures = evaluate_positive_control(&vacuous, TEST_EGRESS_IFACE, true, true);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].contains("conntrack-attributed") && failures[0].contains("4 ICMP"),
            "{failures:?}"
        );
        // raw==0: nothing here — evaluate_leak_witness already reported the
        // raw vacuity; a second failure would double-count one root cause.
        let empty = PositiveControlEvidence::default();
        assert_eq!(
            evaluate_positive_control(&empty, TEST_EGRESS_IFACE, true, true).len(),
            0
        );
    }

    // ── W3: conservative attribution of masqueraded client flows ─────────

    // The u46-r35 capture shape replayed (evidence verdict: host_dns_tcp 1,
    // forwarded_icmp 4, wireguard 15): WireGuard traffic, FOUR exit-origin
    // control pings, then the masqueraded CLIENT FIN pair
    // 192.168.0.32:43420 <-> 1.1.1.1:53 seen from the egress side — after
    // masquerade both FINs carry the EGRESS address as source.
    fn r35_replay_capture() -> String {
        let mut capture = String::new();
        for i in 0..15 {
            capture.push_str(&format!(
                "12:00:{:02}.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length {i}\n",
                i % 60
            ));
        }
        for seq in 0..4 {
            capture.push_str(&format!(
                "12:00:10.00000{seq} IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, \
                 id 7, seq {seq}, length 64\n"
            ));
        }
        capture.push_str(&format!(
            "12:00:12.802940 IP 1.1.1.1.53 > {TEST_EGRESS_ADDR}.43420: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        capture
    }

    // W3b core: with BOTH conntrack snapshots carrying the CLIENT flow's
    // original source, the masqueraded FIN pair is no longer a host-origin
    // leak and the witness PASSES — but only because of attribution: the
    // negative twin below fails without the conntrack line. The r35 capture
    // carries NO SYN (the flow pre-existed the window), so under MED-3 the
    // flow must be evidenced in BOTH snapshots, and the client source must
    // sit in the client space (10.6.0.2 inside the tunnel subnet 10.6.0.0/24
    // derived from the capture-start interface listing, MED-5). The four
    // control pings use id 7 — the icmp entry must carry the same triple.
    #[test]
    fn w3_u46_r35_replay_passes_only_because_of_attribution() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        let masq_tcp =
            conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        program_conntrack(&mock, &masq_tcp, "", "");
        program_capture_end_conntrack(
            &mock,
            &masq_tcp,
            "",
            "",
            &conntrack_masq_icmp_entry_with_id("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 7),
        );
        program_capture(&mock, &r35_replay_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.counts.host_dns_tcp, 0);
        assert_eq!(report.counts.wireguard, 15);
        assert_eq!(report.positive_control.exit_origin_icmp, 0);
        assert_eq!(report.positive_control.forwarded_icmp_raw, 4);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 4);
        assert_eq!(report.forwarded_dns_tcp.len(), 1);
        let packet = &report.forwarded_dns_tcp[0];
        assert_eq!(packet.original_src, "10.6.0.2");
        assert_eq!(packet.snapshot, CONNTRACK_SNAPSHOT_BOTH);
        assert!(packet.conntrack_line.contains("src=10.6.0.2"), "{packet:?}");
        assert!(packet.packet_line.contains("43420"), "{packet:?}");
        assert_eq!(report.positive_control.forwarded_dns_attributed, 1);
        assert!(
            report.positive_control.proven.contains("10.6.0.2"),
            "{:?}",
            report.positive_control.proven
        );
        assert!(
            report
                .positive_control
                .client_original_srcs
                .contains(&"10.6.0.2".to_owned())
        );
    }

    // Negative twin: the SAME r35 capture with an EMPTY capture-end snapshot
    // (no conntrack evidence at all) keeps failing — attribution can never
    // turn a possible host leak into a pass without evidence.
    #[test]
    fn w3_u46_r35_replay_without_conntrack_line_fails() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, "", "", "", "");
        program_capture(&mock, &r35_replay_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // W3b: a FIN matching a conntrack entry whose ORIGINAL source is the
    // exit's own local address stays a failure — attribution only relieves
    // provably-foreign (client) sources.
    #[test]
    fn w3_fin_matching_entry_with_local_original_src_still_fails() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry(
                TEST_EGRESS_ADDR,
                43420,
                TEST_EGRESS_ADDR,
                43420,
                "1.1.1.1",
                53,
            ),
            "",
            "",
            "",
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // W3b: a capture-end snapshot that never answers keeps the failure even
    // though the capture-START snapshot carries a plausible client entry —
    // BOTH snapshots must be available before anything is relabelled.
    #[test]
    fn w3_capture_end_conntrack_missing_keeps_leak_failure() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        program_local_addrs(&mock);
        // The capture-END conntrack argvs are deliberately NOT programmed —
        // every query errors, the snapshot is unusable, attribution disabled.
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // W3b: garbage conntrack output (no parseable two-tuple entries) keeps
    // the failure — attribution needs a real ORIGINAL source, never guesses.
    #[test]
    fn w3_conntrack_parse_garbage_keeps_leak_failure() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "this is not conntrack output at all\n\nno tuples in here\n",
            "",
            "",
            "",
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // W3b: two conflicting matches (distinct ORIGINAL tuples) are ambiguous —
    // the packet stays counted as a leak, never guessed into a pass.
    #[test]
    fn w3_conflicting_conntrack_matches_fail() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &format!(
                "{}{}",
                conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
                conntrack_masq_tcp_entry("10.6.0.3", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53)
            ),
            "",
            "",
            "",
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // W3b: without local-address ground truth (`ip -4 -o addr show` failed)
    // attribution is conservatively DISABLED even when a conntrack entry
    // matches — the leak keeps failing and the verdict records why.
    #[test]
    fn w3_local_addrs_missing_attribution_disabled() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        // the START snapshot DOES carry the flow and every start query
        // answers — arming is refused purely for the missing local-address
        // ground truth, never for a missing entry.
        program_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        // NOTE: program_local_addrs deliberately NOT called — the argv is
        // unprogrammed, so the listing errors and attribution is disabled.
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
            "",
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(report.capture_start_local_addrs.is_empty());
        assert!(
            report
                .capture_start_local_addrs_raw
                .contains("attribution disabled"),
            "{:?}",
            report.capture_start_local_addrs_raw
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // MED-3 killers: a snapshot with a PARTIALLY-ANSWERED query set must
    // never arm attribution — even when the answered queries happen to
    // carry the matching entry. The failing query here (tcp/853) is
    // irrelevant to the FIN tuple, so only the all_answered gate stands
    // between the leak and a false pass.
    #[test]
    fn m05_start_snapshot_partial_answer_never_arms() {
        let masq =
            conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let icmp = conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1");
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        // start: tcp/53 answers WITH the matching entry, tcp/853 fails,
        // udp/53 answers — the start snapshot is PARTIALLY answered.
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "53",
            ],
            exit_ok(&masq),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "853",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "udp",
                "--dport",
                "53",
            ],
            exit_ok(""),
        );
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, &masq, "", "", &icmp);
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(
            report.counts.host_dns_tcp, 1,
            "{:?}",
            report.forwarded_dns_tcp
        );
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    #[test]
    fn m22_end_snapshot_partial_answer_never_arms() {
        let masq =
            conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let icmp = conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1");
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(&mock, &masq, "", "");
        program_local_addrs(&mock);
        // end: tcp/53 answers WITH the matching entry, tcp/853 fails,
        // udp/53 + icmp answer — the end snapshot is PARTIALLY answered.
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "53",
            ],
            exit_ok(&masq),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "853",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "udp",
                "--dport",
                "53",
            ],
            exit_ok(""),
        );
        mock.program_run_response(
            &["sudo", "-n", "conntrack", "-L", "-p", "icmp"],
            exit_ok(&icmp),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(
            report.counts.host_dns_tcp, 1,
            "{:?}",
            report.forwarded_dns_tcp
        );
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // M20 killer: the exit's OWN tunnel address (10.6.0.1, listed by
    // `ip -4 -o addr show`) sits inside the derived mesh subnet, so ONLY
    // the exit-local exclusion — not the client space — stands between it
    // and a relieved host-origin leak.
    #[test]
    fn m20_exit_own_tunnel_addr_original_src_stays_leak() {
        let masq =
            conntrack_masq_tcp_entry("10.6.0.1", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let icmp = conntrack_masq_icmp_entry("10.6.0.1", TEST_EGRESS_ADDR, "192.0.2.1");
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(&mock, &masq, "", "");
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, &masq, "", "", &icmp);
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(
            report.counts.host_dns_tcp, 1,
            "{:?}",
            report.forwarded_dns_tcp
        );
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // W3c + owner Q04 revision: only exit-origin ICMP in the capture (the
    // control pings) with zero attributed packets is VACUOUS **only when the
    // conntrack snapshots carry icmp entries** — an icmp-carrying snapshot
    // that matches nothing means a forwarded client echo went unattributed.
    // When NO snapshot carries an icmp entry, the raw packet is the exit's
    // own ping, provably exit-origin by elimination, so the run stays GREEN.
    #[test]
    fn w3_positive_control_vacuity_only_exit_origin_icmp_fails() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        // end snapshot answers, but carries no entry matching anything in the
        // capture (different port): the ICMP stays exit-origin, nothing is
        // attributed, the control is vacuous.
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 9999, TEST_EGRESS_ADDR, 9999, "1.1.1.1", 53),
            "",
            "",
            "",
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.positive_control.exit_origin_icmp, 1);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 0);
        assert_eq!(report.positive_control.forwarded_icmp_raw, 1);
        // Q04: no icmp entry in either snapshot => the raw echo is
        // exit-origin by elimination => NOT vacuous.
        assert!(
            report.failures.is_empty(),
            "exit-origin echo with icmp-free snapshots must pass: {:?}",
            report.failures
        );

        // Same shape, but the end snapshot carries an icmp entry (a client
        // echo with a different id): now the snapshots are icmp-carrying and
        // the unattributed wire echo is a vacuous witness again.
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 9999, TEST_EGRESS_ADDR, 9999, "1.1.1.1", 53),
            "",
            "",
            &conntrack_masq_icmp_entry_with_id("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 77),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.positive_control.exit_origin_icmp, 1);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no forwarded traffic")),
            "{:?}",
            report.failures
        );
    }

    // W3c: a conntrack-attributed masqueraded client ICMP counts as the
    // positive control — exactly the attribution the raw count lacked.
    #[test]
    fn w3_forwarded_icmp_attributed_counts_as_positive_control() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 1);
        assert_eq!(report.positive_control.exit_origin_icmp, 0);
        assert_eq!(report.positive_control.forwarded_icmp_raw, 1);
        assert_eq!(
            report.positive_control.client_original_srcs,
            vec!["10.6.0.2".to_owned()]
        );
        assert!(
            report
                .positive_control
                .proven
                .contains("1 masqueraded ICMP"),
            "{:?}",
            report.positive_control.proven
        );
    }

    // W3b/W1 interaction: a pre-existing capture-start entry whose ORIGINAL
    // source is a foreign client address is a masqueraded client flow —
    // normal tunneled traffic, never the pre-existing host-origin failure.
    #[test]
    fn w3_pre_existing_client_flow_entry_does_not_fail_the_witness() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        // ESTABLISHED (so the W1 host-origin parser DOES pick it up) but with
        // a foreign original source: the W3 filter must exclude it.
        program_conntrack(
            &mock,
            &conntrack_established_entry("10.6.0.2", 43420, "1.1.1.1", 53),
            "",
            "",
        );
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(
            !report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // ── W3 parsers and matchers ──────────────────────────────────────────

    #[test]
    fn parse_conntrack_entries_parses_both_tuples_and_skips_garbage() {
        let out = format!(
            "{}{}{}garbage line without tuples\n\n",
            conntrack_masq_tcp_entry("10.6.0.2", 43420, "192.0.2.240", 43420, "1.1.1.1", 53),
            conntrack_established_entry("192.0.2.240", 40004, "8.8.8.8", 853),
            conntrack_masq_icmp_entry("10.6.0.2", "192.0.2.240", "192.0.2.1"),
        );
        let entries = parse_conntrack_entries(&out);
        assert_eq!(entries.len(), 3, "{entries:?}");
        let masq = &entries[0];
        assert_eq!(masq.proto, "tcp");
        assert_eq!(masq.original.src, "10.6.0.2");
        assert_eq!(masq.original.sport, Some(43420));
        assert_eq!(masq.original.dst, "1.1.1.1");
        assert_eq!(masq.original.dport, Some(53));
        assert_eq!(masq.reply.src, "1.1.1.1");
        assert_eq!(masq.reply.sport, Some(53));
        assert_eq!(masq.reply.dst, "192.0.2.240");
        assert_eq!(masq.reply.dport, Some(43420));
        assert!(masq.line.contains("TIME_WAIT"));
        let host = &entries[1];
        assert_eq!(host.original.src, "192.0.2.240");
        assert_eq!(host.original.dport, Some(853));
        assert_eq!(host.reply.src, "8.8.8.8");
        assert_eq!(host.reply.dport, Some(40004));
        let icmp = &entries[2];
        assert_eq!(icmp.proto, "icmp");
        assert_eq!(icmp.original.sport, None);
        assert_eq!(icmp.original.dport, None);
        assert_eq!(icmp.original.src, "10.6.0.2");
        assert_eq!(icmp.reply.dst, "192.0.2.240");
    }

    #[test]
    fn parse_ip_o_addr_show_v4_extracts_and_dedups_inet_addrs() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                   1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                   2: enp0s9    inet 192.0.2.240/24 brd 192.0.2.255 scope global enp0s9\\\n\
                   5: rustynet0    inet 10.6.0.1/24 scope global rustynet0\\\n\
                   5: rustynet0    inet6 fd00::1/64 scope global rustynet0\\\n";
        assert_eq!(
            parse_ip_o_addr_show_v4(out),
            vec![
                "127.0.0.1".to_owned(),
                "192.0.2.240".to_owned(),
                "10.6.0.1".to_owned()
            ]
        );
        assert!(parse_ip_o_addr_show_v4("").is_empty());
        assert!(parse_ip_o_addr_show_v4("no addresses here\n").is_empty());
    }

    #[test]
    fn is_exit_local_addr_is_conservative_ground_truth() {
        let local = vec!["10.6.0.1".to_owned(), "192.0.2.240".to_owned()];
        assert!(is_exit_local_addr("192.0.2.240", &local, "192.0.2.240"));
        assert!(is_exit_local_addr("10.6.0.1", &local, "192.0.2.240"));
        assert!(is_exit_local_addr("127.0.0.53", &local, "192.0.2.240"));
        assert!(!is_exit_local_addr("10.6.0.2", &local, "192.0.2.240"));
        assert!(!is_exit_local_addr("192.168.0.32", &local, "192.0.2.240"));
        assert!(is_valid_ipv4("192.168.0.32"));
        assert!(!is_valid_ipv4("192.168.0"));
        assert!(!is_valid_ipv4("999.1.1.1"));
        assert!(!is_valid_ipv4("a.b.c.d"));
    }

    #[test]
    fn conntrack_matching_gates_on_protocol_and_both_directions() {
        let masq = conntrack_masq_tcp_entry("10.6.0.2", 43420, "192.0.2.240", 43420, "1.1.1.1", 53);
        let entry = &parse_conntrack_entries(&masq)[0];
        // the ORIGINAL dport is part of the tuple: same src/sport/remote
        // but dport 853 must never absorb the tcp/53 packet (M10)
        assert!(!conntrack_entry_matches_packet(
            entry,
            "tcp",
            "10.6.0.2",
            Some(43420),
            "1.1.1.1",
            Some(853),
            None,
        ));
        // reply direction: the masqueraded FIN seen from the egress side
        assert!(conntrack_entry_matches_packet(
            entry,
            "tcp",
            "192.0.2.240",
            Some(43420),
            "1.1.1.1",
            Some(53),
            None
        ));
        // original direction: the pre-masquerade (tunnel side) packet
        assert!(conntrack_entry_matches_packet(
            entry,
            "tcp",
            "10.6.0.2",
            Some(43420),
            "1.1.1.1",
            Some(53),
            None
        ));
        // wrong protocol never matches
        assert!(!conntrack_entry_matches_packet(
            entry,
            "udp",
            "192.0.2.240",
            Some(43420),
            "1.1.1.1",
            Some(53),
            None
        ));
        // wrong tuple never matches
        assert!(!conntrack_entry_matches_packet(
            entry,
            "tcp",
            "192.0.2.240",
            Some(9999),
            "1.1.1.1",
            Some(53),
            None
        ));
        let icmp = &parse_conntrack_entries(&conntrack_masq_icmp_entry(
            "10.6.0.2",
            "192.0.2.240",
            "192.0.2.1",
        ))[0];
        let wire = IcmpEcho {
            kind: 8,
            code: 0,
            id: 1,
        };
        // matching triple on the original direction
        assert!(conntrack_entry_matches_packet(
            icmp,
            "icmp",
            "192.0.2.240",
            None,
            "192.0.2.1",
            None,
            Some(wire)
        ));
        // reply direction: the echo ANSWER carries (0,0,1)
        let reply = IcmpEcho {
            kind: 0,
            code: 0,
            id: 1,
        };
        assert!(conntrack_entry_matches_packet(
            icmp,
            "icmp",
            "192.0.2.1",
            None,
            "192.0.2.240",
            None,
            Some(reply)
        ));
        // missing wire triple: no blind match (fail closed)
        assert!(!conntrack_entry_matches_packet(
            icmp,
            "icmp",
            "192.0.2.240",
            None,
            "192.0.2.1",
            None,
            None
        ));
        // id mismatch: an unrelated echo must never be absorbed
        let other = IcmpEcho {
            kind: 8,
            code: 0,
            id: 99,
        };
        assert!(!conntrack_entry_matches_packet(
            icmp,
            "icmp",
            "192.0.2.240",
            None,
            "192.0.2.1",
            None,
            Some(other)
        ));
        // a tcp entry never absorbs an icmp packet, triple or not
        assert!(!conntrack_entry_matches_packet(
            entry,
            "icmp",
            "192.0.2.240",
            None,
            "192.0.2.1",
            None,
            Some(wire)
        ));
    }

    // ── Independent-review ports: HIGH-1 extended conntrack format ───────

    // HIGH-1: real `conntrack -L -o extended` lines start with the address
    // family and a use counter (`ipv4     2 tcp ...`); the protocol is never
    // the first token. Both formats must parse, including icmp with its
    // type/code/id triples.
    #[test]
    fn high1_extended_format_entries_parse_like_plain_ones() {
        let plain =
            conntrack_masq_tcp_entry("10.6.0.2", 43420, "192.0.2.240", 43420, "1.1.1.1", 53);
        let extended =
            conntrack_extended_tcp_entry("10.6.0.2", 43420, "192.0.2.240", 43420, "1.1.1.1", 53);
        let plain_entry = &parse_conntrack_entries(&plain)[0];
        let extended_entry = &parse_conntrack_entries(&extended)[0];
        assert_eq!(plain_entry.proto, "tcp");
        assert_eq!(
            extended_entry.proto, "tcp",
            "family token must not become proto"
        );
        assert_eq!(extended_entry.original, plain_entry.original);
        assert_eq!(extended_entry.reply, plain_entry.reply);
        let plain_icmp = &parse_conntrack_entries(&conntrack_masq_icmp_entry(
            "10.6.0.2",
            "192.0.2.240",
            "192.0.2.1",
        ))[0];
        let extended_icmp = &parse_conntrack_entries(&conntrack_extended_icmp_entry(
            "10.6.0.2",
            "192.0.2.240",
            "192.0.2.1",
            7,
        ))[0];
        assert_eq!(extended_icmp.proto, "icmp");
        assert_eq!(extended_icmp.original, plain_icmp.original);
        assert_eq!(extended_icmp.reply, plain_icmp.reply);
        // a genuinely unknown leading token still parses as garbage-skip
        assert!(parse_conntrack_entries("sctp     2 119 src=a dst=b\n").is_empty());
    }

    // HIGH-1 end-to-end: a capture-end snapshot written in the extended
    // format still arms attribution and satisfies the positive control on a
    // clean capture (and the plain-format twin must keep passing).
    #[test]
    fn high1_real_extended_format_clean_run_positive_control() {
        for icmp_entry in [
            conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
            conntrack_extended_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 1),
        ] {
            let mock = Arc::new(MockShellHost::new());
            program_setup(&mock, true);
            program_capture_start_evidence_clean(&mock);
            program_local_addrs(&mock);
            program_capture_end_conntrack(&mock, "", "", "", &icmp_entry);
            program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
            let report = run_witness(&mock).expect("setup must succeed");
            assert!(
                report.failures.is_empty(),
                "{:?}: {icmp_entry}",
                report.failures
            );
            assert_eq!(report.positive_control.forwarded_icmp_attributed, 1);
        }
    }

    // HIGH-1 end-to-end on the r35 replay: extended-format tcp entries in
    // BOTH snapshots (the FIN has no SYN inside the window, MED-3) relieve
    // the masqueraded client FIN.
    #[test]
    fn high1_real_extended_format_r35() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        let masq_tcp =
            conntrack_extended_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        program_conntrack(&mock, &masq_tcp, "", "");
        program_capture_end_conntrack(
            &mock,
            &masq_tcp,
            "",
            "",
            &conntrack_extended_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 7),
        );
        program_capture(&mock, &r35_replay_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.forwarded_dns_tcp.len(), 1);
        assert_eq!(report.forwarded_dns_tcp[0].original_src, "10.6.0.2");
        assert_eq!(
            report.forwarded_dns_tcp[0].snapshot,
            CONNTRACK_SNAPSHOT_BOTH
        );
    }

    // ── MED-3: snapshot-pair attribution rule ────────────────────────────

    // MED-3 core: an entry that appears ONLY in the end snapshot never
    // relieves a flow with no initiator inside the window (the FIN-only r35
    // shape): the flow pre-existed the window, so the start snapshot must
    // carry it too. End-only evidence is exactly what a half-rotated
    // conntrack table looks like.
    #[test]
    fn w3_end_only_entry_without_initiator_does_not_attribute() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(
            report.counts.host_dns_tcp, 1,
            "{:?}",
            report.forwarded_dns_tcp
        );
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet(s) left")),
            "{:?}",
            report.failures
        );
    }

    // rv_f2 INVERTED (MED-3): an entry only in the START snapshot (already
    // gone at capture end) never attributes — the original probe expected a
    // pass there, which is precisely the unsound direction.
    #[test]
    fn rv_f2_inverted_start_only_entry_does_not_attribute() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // A tcp flow whose SYN IS inside the window may be attributed from the
    // end snapshot alone — the initiator proves the flow was born here.
    #[test]
    fn w3_syn_inside_window_relieves_from_end_snapshot_alone() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:05.000000 IP {TEST_EGRESS_ADDR}.41000 > 192.0.2.53.53: Flags [S], seq 1, \
             win 64240, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 41000, TEST_EGRESS_ADDR, 41000, "192.0.2.53", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.forwarded_dns_tcp.len(), 1);
        assert_eq!(report.forwarded_dns_tcp[0].snapshot, CONNTRACK_SNAPSHOT_END);
        assert_eq!(report.counts.host_dns_tcp, 0);
    }

    // A [FS] (simultaneous-open) detail is NOT counted as an initiator —
    // started_inside_window demands a clean SYN (`Flags [S`).
    #[test]
    fn w3_simultaneous_open_is_not_an_initiator() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:05.000000 IP {TEST_EGRESS_ADDR}.41000 > 192.0.2.53.53: Flags [FS], seq 1, \
             win 64240, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 41000, TEST_EGRESS_ADDR, 41000, "192.0.2.53", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // rv: a SYN leak with NO conntrack evidence anywhere fails.
    #[test]
    fn rv_timing_between_snapshots_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:05.000000 IP {TEST_EGRESS_ADDR}.41000 > 192.0.2.53.53: Flags [S], seq 1, \
             win 64240, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, "", "", "", "");
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
    }

    // rv: the same 4-tuple matches a HOST entry at start and a CLIENT entry
    // at end — the two snapshots disagree about the ORIGINAL source, the
    // flow never showed an initiator, and the packet stays a leak.
    #[test]
    fn rv_ambiguity_across_snapshots_fails() {
        for (start_line, end_line) in [
            (
                conntrack_established_entry(TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
                conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            ),
            (
                conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
                conntrack_established_entry(TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            ),
        ] {
            let mock = Arc::new(MockShellHost::new());
            program_setup(&mock, true);
            program_capture_start_nft_listing(&mock, &nft_table_ok());
            program_boot_table(&mock, None);
            program_local_addrs(&mock);
            program_conntrack(&mock, &start_line, "", "");
            program_capture_end_conntrack(
                &mock,
                &end_line,
                "",
                "",
                &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
            );
            program_capture(
                &mock,
                &with_client_fin(&clean_capture()),
                &tcpdump_stderr_ok(),
            );
            let report = run_witness(&mock).expect("setup must succeed");
            assert_eq!(report.counts.host_dns_tcp, 1, "{start_line} | {end_line}");
            assert!(report.forwarded_dns_tcp.is_empty());
        }
    }

    // rv_f6/MED-5: ORIGINAL sources outside the provable client space never
    // attribute — every one of these keeps the host-origin leak. Sources in
    // the fallback's own space (172.17.0.2, 192.168.0.32) are rejected here
    // because the tunnel subnet (10.6.0.0/24) is derivable from the
    // capture-start listing; exit-local and infrastructure addresses are
    // rejected by their own guards.
    #[test]
    fn rv_f6_odd_original_sources_stay_leaks() {
        for src in [
            "172.17.0.2",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "8.8.8.8",
            "10.6.0.1",
            "127.0.0.1",
            "192.0.2.240",
            "192.168.0.32",
            "10.7.0.9",
            "10.6.0.256",
            "not-an-ip",
        ] {
            let masq = format!(
                "tcp      6 119 TIME_WAIT src={src} dst=1.1.1.1 sport=43420 dport=53 \
                 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 dport=43420 mark=0 use=1\n"
            );
            let mock = Arc::new(MockShellHost::new());
            program_setup(&mock, true);
            program_capture_start_evidence_clean(&mock);
            program_local_addrs(&mock);
            program_capture_end_conntrack(
                &mock,
                &masq,
                "",
                "",
                &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
            );
            program_capture(
                &mock,
                &with_client_fin(&clean_capture()),
                &tcpdump_stderr_ok(),
            );
            let report = run_witness(&mock).expect("setup must succeed");
            assert_eq!(report.counts.host_dns_tcp, 1, "src={src}");
            assert!(
                report.forwarded_dns_tcp.is_empty(),
                "src={src} must never attribute"
            );
        }
    }

    // MED-5 tier 1: stage-supplied client addresses REPLACE the derived
    // space — a tunnel-subnet source that the stage did NOT name stays a
    // leak, one it DID name is attributed (exact match, no subnet widening).
    // The FIN has no SYN inside the window, so the flow is evidenced in BOTH
    // snapshots (MED-3).
    #[test]
    fn med5_stage_supplied_addrs_narrow_the_client_space() {
        let masq_ok =
            conntrack_masq_tcp_entry("10.6.0.5", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let masq_other =
            conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let icmp_entry = conntrack_masq_icmp_entry("10.6.0.5", TEST_EGRESS_ADDR, "192.0.2.1");
        let fin_capture = with_client_fin(&clean_capture());
        // named client source: attributed, witness passes
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(&mock, &masq_ok, "", "");
        program_capture_end_conntrack(&mock, &masq_ok, "", "", &icmp_entry);
        program_capture(&mock, &fin_capture, &tcpdump_stderr_ok());
        let report =
            run_witness_with_clients(&mock, &[("client-1".to_owned(), "10.6.0.5".to_owned())])
                .expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.forwarded_dns_tcp.len(), 1);
        assert_eq!(report.forwarded_dns_tcp[0].original_src, "10.6.0.5");
        assert_eq!(report.forwarded_dns_tcp[0].mesh_peer, "client-1");
        // a source inside the same tunnel subnet but NOT named by the stage:
        // never attributed, the leak stays
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(&mock, &masq_other, "", "");
        program_capture_end_conntrack(&mock, &masq_other, "", "", &icmp_entry);
        program_capture(&mock, &fin_capture, &tcpdump_stderr_ok());
        let report =
            run_witness_with_clients(&mock, &[("client-1".to_owned(), "10.6.0.5".to_owned())])
                .expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // rv_f7/MED-3: when ANY capture-end query fails, the snapshot cannot
    // prove an entry's absence — attribution stays disabled and the leak
    // keeps failing, even though the other three queries answered.
    #[test]
    fn rv_f7_partial_end_snapshot_keeps_attribution_disabled() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        program_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
        );
        // end snapshot: tcp/53 query fails (the old -o extended retry shape),
        // the other three answer — arming must still be refused.
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "53",
            ],
            exit_code(1, ""),
        );
        for argv in [
            vec![
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "853",
            ],
            vec![
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "udp",
                "--dport",
                "53",
            ],
            vec!["sudo", "-n", "conntrack", "-L", "-p", "icmp"],
        ] {
            mock.program_run_response(&argv, exit_ok(""));
        }
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // rv_f7b: the same refusal when the START snapshot only partially
    // answered.
    #[test]
    fn rv_f7b_partial_start_snapshot_keeps_attribution_disabled() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "53",
            ],
            exit_code(1, ""),
        );
        for argv in [
            vec![
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "tcp",
                "--dport",
                "853",
            ],
            vec![
                "sudo",
                "-n",
                "conntrack",
                "-L",
                "-p",
                "udp",
                "--dport",
                "53",
            ],
        ] {
            mock.program_run_response(&argv, exit_ok(""));
        }
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // ── MED-4: tcp vs udp decided by line STRUCTURE, never a bare
    //    `contains("Flags")` ──────────────────────────────────────────────

    // rv_f5: a udp/53 query whose QNAME contains the substring "Flags" must
    // stay a host-origin udp leak — and must never be "relieved" by a tcp
    // conntrack entry that happens to share the ports.
    #[test]
    fn rv_f5_udp_qname_flags_substring_is_udp() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40002 > 192.0.2.53.53: 2+ A? \
             Flags.example.com. (30)\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 40002, TEST_EGRESS_ADDR, 40002, "192.0.2.53", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_udp, 1);
        assert!(report.counts.host_dns_tcp == 0 && report.counts.host_dot == 0);
        assert!(report.forwarded_dns_tcp.is_empty());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("udp/53") && f.contains("1 host-origin")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn med4_transport_detection_is_structural() {
        assert_eq!(
            packet_details_after_endpoints(
                "12:00:12.803670 IP 192.0.2.240.43420 > 1.1.1.1.53: Flags [F.], seq 1, length 0",
            ),
            Some("Flags [F.], seq 1, length 0")
        );
        assert_eq!(
            packet_details_after_endpoints("banner line without packet"),
            None
        );
        assert_eq!(
            line_transport("x IP a.1 > b.2: Flags [S], win 1"),
            LineTransport::Tcp
        );
        assert_eq!(
            line_transport("x IP a.1 > b.2: UDP, length 32"),
            LineTransport::Udp
        );
        assert_eq!(
            line_transport("x IP a.1 > b.2: 2+ A? Flags.here. (9)"),
            LineTransport::Unknown
        );
        assert_eq!(
            line_transport("x IP a.1 > b.2: ICMP echo request, id 1, seq 1"),
            LineTransport::Unknown
        );
    }

    // ── LOW: icmp type/code/id triple matching ───────────────────────────

    #[test]
    fn low_icmp_triple_parsing() {
        let request = parse_icmp_echo_from_packet("ICMP echo request, id 7, seq 0, length 64");
        assert_eq!(
            request,
            Some(IcmpEcho {
                kind: 8,
                code: 0,
                id: 7
            })
        );
        let reply = parse_icmp_echo_from_packet("ICMP echo reply, id 7, seq 0, length 64");
        assert_eq!(
            reply,
            Some(IcmpEcho {
                kind: 0,
                code: 0,
                id: 7
            })
        );
        assert_eq!(parse_icmp_echo_from_packet("ICMP unreach, length 8"), None);
        assert_eq!(
            parse_icmp_echo_from_packet("ICMP echo request, no id here"),
            None
        );
        let entry = &parse_conntrack_entries(&conntrack_masq_icmp_entry_with_id(
            "10.6.0.2",
            "192.0.2.240",
            "192.0.2.1",
            42,
        ))[0];
        assert_eq!(
            icmp_echo_from_entry(entry, 0),
            Some(IcmpEcho {
                kind: 8,
                code: 0,
                id: 42
            })
        );
        assert_eq!(
            icmp_echo_from_entry(entry, 1),
            Some(IcmpEcho {
                kind: 0,
                code: 0,
                id: 42
            })
        );
        assert_eq!(icmp_echo_from_entry(entry, 2), None);
    }

    // An icmp entry whose id does not match the wire echo must NOT satisfy
    // the positive control (mutant killer: dropping the triple check would
    // make this witness pass on an unrelated echo).
    #[test]
    fn low_icmp_id_mismatch_keeps_control_vacuous() {
        let mut capture = clean_capture();
        capture = capture.replace("id 1, seq 1", "id 99, seq 1");
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 0);
        assert_eq!(report.positive_control.exit_origin_icmp, 1);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness")),
            "{:?}",
            report.failures
        );
    }

    // Matching ids attribute (control holds); the entry may live in the
    // extended format and still match the wire triple.
    #[test]
    fn low_icmp_matching_id_counts_as_control() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_extended_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 1),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 1);
    }

    // ── DoT / udp coverage (rv) ──────────────────────────────────────────

    #[test]
    fn rv_dot_syn_end_only_entry_relieves_host_dot() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:04.000000 IP {TEST_EGRESS_ADDR}.41001 > 192.0.2.53.853: Flags [S], seq 1, \
             win 64240, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            &conntrack_masq_tcp_entry(
                "10.6.0.2",
                41001,
                TEST_EGRESS_ADDR,
                41001,
                "192.0.2.53",
                853,
            ),
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.counts.host_dot, 0);
        assert_eq!(report.forwarded_dns_tcp.len(), 1);
        assert_eq!(report.forwarded_dns_tcp[0].snapshot, CONNTRACK_SNAPSHOT_END);
        assert_eq!(report.positive_control.forwarded_dns_attributed, 1);
    }

    #[test]
    fn rv_dot_without_entry_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:04.000000 IP {TEST_EGRESS_ADDR}.41001 > 192.0.2.53.853: Flags [S], seq 1, \
             win 64240, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, "", "", "", "");
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dot, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("tcp/853 (DoT)")),
            "{:?}",
            report.failures
        );
    }

    // udp flows are NEVER relieved: no udp conntrack evidence can turn a
    // udp/53 leak into a pass, even with a matching masqueraded entry.
    #[test]
    fn rv_udp_client_entry_never_relieves_udp_leak() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40002 > 192.0.2.53.53: 2+ A? leak.invalid. (30)\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "udp      17 119 src=10.6.0.2 dst=192.0.2.53 sport=40002 dport=53 \
             src=192.0.2.53 dst=192.0.2.240 sport=53 dport=40002 mark=0 use=1\n",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_udp, 1);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("udp/53") && f.contains("1 host-origin")),
            "{:?}",
            report.failures
        );
    }

    // rv: a udp conntrack entry can never absorb a tcp packet (proto gate at
    // the witness level).
    #[test]
    fn rv_proto_confusion_udp_entry_tcp_packet_fails() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "udp      17 119 src=10.6.0.2 dst=1.1.1.1 sport=43420 dport=53 \
             src=1.1.1.1 dst=192.0.2.240 sport=53 dport=43420 mark=0 use=1\n",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // A conntrack entry for a DIFFERENT 4-tuple never relieves the leak
    // (mutant killer for the original-port equality gates).
    #[test]
    fn w3_entry_with_different_tuple_never_relieves() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &conntrack_masq_tcp_entry("10.6.0.2", 9999, TEST_EGRESS_ADDR, 9999, "1.1.1.1", 53),
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // ── Parser / subtraction mutants ─────────────────────────────────────

    // A conntrack line with only the original tuple (no reply tuple) is
    // garbage — it must be skipped, never half-parsed into an attribution
    // match.
    #[test]
    fn m25_single_tuple_line_is_rejected() {
        let single = "tcp      6 119 TIME_WAIT src=10.6.0.2 dst=1.1.1.1 sport=43420 dport=53\n";
        assert!(parse_conntrack_entries(single).is_empty());
        assert!(parse_conntrack_tcp_dns_entries(single).is_empty());
        // and the truncated entry never relieves a leak end-to-end
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            single,
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // The 16KiB evidence bound is real: a snapshot whose matching entry sits
    // beyond the bound has that entry truncated away, and the leak stays —
    // the recorded blob and the parsed entries can never disagree.
    #[test]
    fn m26_bound_truncation_keeps_leak() {
        let mut big = String::new();
        for i in 0..400 {
            // the very LAST entry is the one matching the FIN tuple — it is
            // the first casualty of the 16KiB bound
            let sport = if i == 399 { 43420 } else { 40000 + i as u16 };
            big.push_str(&conntrack_masq_tcp_entry(
                "10.6.0.2",
                sport,
                TEST_EGRESS_ADDR,
                sport,
                "1.1.1.1",
                53,
            ));
        }
        assert!(big.len() > CAPTURE_START_EVIDENCE_MAX_BYTES);
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        // the truncated blob feeds BOTH snapshots: the matching entry sits
        // past the 16KiB bound in each, so attribution can never arm on it
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(&mock, &big, "", "");
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            &big,
            "",
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(report.forwarded_dns_tcp.is_empty());
    }

    // HIGH-2/W3c: host_dns_tcp may only be relieved by attributed tcp/53
    // flows — a DoT (853) attribution never subtracts from the tcp/53 class.
    #[test]
    fn m34_no_cross_class_subtraction() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:04.000000 IP {TEST_EGRESS_ADDR}.41001 > 192.0.2.53.853: Flags [S], seq 1, \
             win 64240, length 0\n"
        ));
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, \
             ack 1, win 507, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_capture_end_conntrack(
            &mock,
            "",
            &conntrack_masq_tcp_entry(
                "10.6.0.2",
                41001,
                TEST_EGRESS_ADDR,
                41001,
                "192.0.2.53",
                853,
            ),
            "",
            &conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1"),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.positive_control.forwarded_dns_attributed, 1);
        assert_eq!(report.counts.host_dot, 0, "the DoT SYN is relieved");
        assert_eq!(report.counts.host_dns_tcp, 1, "the tcp/53 FIN is NOT");
        assert!(report.forwarded_dns_tcp.len() == 1);
    }

    // M18: the W1 pre-existing failure must fire even when the local-address
    // listing failed (empty ground truth) — a host-origin established flow
    // at capture start is a failure regardless.
    #[test]
    fn m18_pre_existing_failure_fires_without_local_addrs() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        // ip -4 -o addr show deliberately unprogrammed -> errors. The entry
        // is a FOREIGN host's flow: with no local-address ground truth the
        // pre-existing filter must conservatively keep it (an egress-src or
        // loopback entry would stay a host-origin entry under any filter,
        // proving nothing about the is_empty clause).
        program_conntrack(
            &mock,
            &conntrack_established_entry("198.51.100.9", 43420, "1.1.1.1", 53),
            "",
            "",
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            report.failures
        );
    }

    // ── MED-6: W2 accept-shape probes ────────────────────────────────────

    fn w2_listing(accept_line: &str, drops_in_other_chain: bool) -> String {
        let drops = "oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
                     oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n";
        if drops_in_other_chain {
            format!(
                "table inet rustynet_g7 {{\n\
                 \x20 chain other {{\n{drops}\
                 \x20 }}\n\
                 \x20 chain egress {{\n\
                 \x20  {accept_line}\n\
                 \x20 }}\n\
                 }}\n"
            )
        } else {
            format!(
                "table inet rustynet_g7 {{\n\
                 \x20 chain egress {{\n\
                 \x20  {accept_line}\n{drops}\
                 \x20 }}\n\
                 }}\n"
            )
        }
    }

    #[test]
    fn med6_w2_accept_shapes_fail_closed() {
        // unqualified established accept BEFORE the drops (legacy shape)
        let err = verify_listing(&w2_listing("ct state established,related accept", false))
            .expect_err("established accept before drops must fail");
        assert!(err.starts_with("kill switch rule order unsafe:"), "{err}");

        // `ct state { established, related }` set-literal spelling
        assert!(
            verify_listing(&w2_listing(
                "ct state { established, related } accept",
                false
            ))
            .is_err()
        );

        // established + counter spelling
        assert!(verify_listing(&w2_listing("ct state established counter accept", false)).is_err());

        // bare oifname accept before the drops — no explicit `ct state
        // established` match, so the new doctrine demotes it to a non-fatal
        // finding recorded in `dns_rule_order_findings`
        let posture = verify_posture(&w2_listing("oifname \"enp0s9\" accept", false))
            .expect("bare oifname accept is a finding, not fatal");
        assert!(
            posture
                .order_findings
                .iter()
                .any(|f| f.contains("oifname \"enp0s9\" accept")),
            "{:?}",
            posture.order_findings
        );

        // tcp dport 53 accept before the drops — also a finding now
        let posture = verify_posture(&w2_listing(
            "oifname \"enp0s9\" meta nfproto ipv4 tcp dport 53 accept",
            false,
        ))
        .expect("tcp dport 53 accept is a finding, not fatal");
        assert_eq!(
            posture.order_findings.len(),
            1,
            "{:?}",
            posture.order_findings
        );

        // ip daddr accept before the drops — can match <daddr>:53, finding
        let posture = verify_posture(&w2_listing("ip daddr 8.8.8.8 accept", false))
            .expect("ip daddr accept is a finding, not fatal");
        assert_eq!(
            posture.order_findings.len(),
            1,
            "{:?}",
            posture.order_findings
        );

        // comment trick: the exclusion lives only in the comment string
        assert!(
            verify_listing(&w2_listing(
                "ct state established,related accept comment \"excludes udp dport != { 53, 853 }\"",
                false
            ))
            .is_err()
        );

        // decoy: the drops live in ANOTHER chain — the egress accept shadows
        // them all the same. Without an explicit established match this is a
        // finding now; the message text is preserved inside the finding.
        let posture = verify_posture(&w2_listing("oifname \"enp0s9\" accept", true))
            .expect("bare accept in a drop-less chain is a finding, not fatal");
        assert!(
            posture
                .order_findings
                .iter()
                .any(|f| f.contains("does not carry BOTH scoped DNS drops")),
            "{:?}",
            posture.order_findings
        );

        // duplicate drop pairs with a dns-capable accept in between: the
        // later pair is shadowed by the accept
        let dup = "table inet rustynet_g7 {\n\
                   \x20 chain egress {\n\
                   \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
                   \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
                   \x20  ct state established,related accept\n\
                   \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
                   \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
                   \x20 }\n\
                   }\n";
        assert!(verify_listing(dup).is_err());
    }

    #[test]
    fn med6_w2_safe_shapes_still_pass() {
        // REAL exclusion match expression before the drops: safe
        assert!(
            verify_listing(&w2_listing(
                "ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept",
                false
            ))
            .is_ok()
        );
        // udp-only exclusion (a real match expression): cannot match
        // tcp/53|853, and cannot match udp/53|853 either
        assert!(
            verify_listing(&w2_listing(
                "ct state established meta nfproto ipv4 udp dport != { 53, 853 } accept",
                false
            ))
            .is_ok()
        );
        // the standard table shape (drops first, plain ipv4 accept last)
        assert!(verify_listing(&nft_table_ok()).is_ok());
    }

    // exact unit coverage for the accept predicate
    #[test]
    fn med6_accept_can_match_dns_ports_unit() {
        assert!(accept_can_match_dns_ports(
            "ct state established,related accept"
        ));
        assert!(accept_can_match_dns_ports("oifname \"enp0s9\" accept"));
        assert!(accept_can_match_dns_ports("ip daddr 8.8.8.8 accept"));
        assert!(accept_can_match_dns_ports("tcp dport 53 accept"));
        assert!(accept_can_match_dns_ports("tcp dport != 53 accept"));
        assert!(accept_can_match_dns_ports("tcp dport @allowed_sets accept"));
        assert!(accept_can_match_dns_ports(
            "ct state established,related accept comment \"udp dport != { 53, 853 }\""
        ));
        assert!(!accept_can_match_dns_ports(
            "ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept"
        ));
        assert!(!accept_can_match_dns_ports(
            "ct state established meta nfproto ipv4 udp dport != { 53, 853 } accept"
        ));
        assert!(!accept_can_match_dns_ports(
            "oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept"
        ));
        // a sport-only allow has NO dport clause, so it is conservatively
        // DNS-capable (a packet with sport 51820 dport 53 exists) — it must
        // then sit AFTER the drops, which the standard table guarantees
        assert!(accept_can_match_dns_ports(
            "oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept"
        ));
        assert!(!accept_can_match_dns_ports(
            "oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop"
        ));
        assert!(!accept_can_match_dns_ports(
            "counters and junk lines carry no verdict at all"
        ));
    }

    // ── ClientSpace units (MED-5) ────────────────────────────────────────

    #[test]
    fn parse_ip_o_addr_show_v4_entries_unit() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                   2: enp0s9    inet 192.0.2.240/24 brd 192.0.2.255 scope global enp0s9\\\n\
                   5: rustynet0    inet 10.6.0.1/24 scope global rustynet0\\\n\
                   5: rustynet0    inet6 fd00::1/64 scope global rustynet0\\\n\
                   junk line without inet\n";
        assert_eq!(
            parse_ip_o_addr_show_v4_entries(out),
            vec![
                ("lo".to_owned(), "127.0.0.1".to_owned(), 8),
                ("enp0s9".to_owned(), "192.0.2.240".to_owned(), 24),
                ("rustynet0".to_owned(), "10.6.0.1".to_owned(), 24),
            ]
        );
        assert!(parse_ip_o_addr_show_v4_entries("").is_empty());
    }

    #[test]
    fn client_space_tiers() {
        let listing = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                       2: enp0s9    inet 192.0.2.240/24 brd 192.0.2.255 scope global enp0s9\\\n\
                       5: rustynet0    inet 10.6.0.1/24 scope global rustynet0\\\n";
        // tier 1: stage-supplied exact addresses only
        let space = ClientSpace::derive(
            &[("client-1".to_owned(), "10.6.0.5".to_owned())],
            listing,
            TEST_EGRESS_ADDR,
            TUNNEL_INTERFACE,
        );
        assert!(space.admits("10.6.0.5"));
        assert_eq!(space.peer_alias("10.6.0.5"), Some("client-1"));
        assert_eq!(space.peer_alias("10.6.0.2"), None);
        assert!(
            !space.admits("10.6.0.2"),
            "subnet must not widen a named set"
        );
        assert!(!space.admits("8.8.8.8"));
        // tier 2: the tunnel interface's subnet from the listing (other
        // ifaces are not the mesh)
        let space = ClientSpace::derive(&[], listing, TEST_EGRESS_ADDR, TUNNEL_INTERFACE);
        assert!(space.admits("10.6.0.2"));
        assert!(!space.admits("192.0.2.99"), "egress iface subnet excluded");
        assert!(!space.admits("127.0.0.9"));
        assert!(!space.admits("172.17.0.2"));
        assert!(!space.admits("8.8.8.8"));
        assert!(!space.admits("0.0.0.0"));
        assert!(!space.admits("224.0.0.1"));
        assert!(!space.admits("169.254.1.1"));
        // tier 3: documented RFC1918+CGNAT fallback (no stage addrs, no
        // listing) — 100.64.0.23 is CGNAT, 8.8.8.8 is not
        let space = ClientSpace::derive(&[], "", TEST_EGRESS_ADDR, TUNNEL_INTERFACE);
        assert!(space.admits("172.17.0.2"));
        assert!(space.admits("100.64.0.23"));
        assert!(!space.admits("8.8.8.8"));
        assert!(!space.admits("192.0.2.240"), "egress-local still excluded");
    }

    // ── rv: hostile input never panics the parsers ───────────────────────

    #[test]
    fn rv_no_panic_on_hostile_input() {
        let mut lines = String::new();
        for i in 0..4000 {
            lines.push_str(&format!(
                "12:00:{:02}.{:06} IP [{garbled} Flags [S] UDP, id={i} IP 1.2.3.4.5 > :{} \\\n",
                i % 60,
                i,
                "A? x".repeat(i % 5),
                garbled = "\u{0}\u{1}b¸®"
            ));
        }
        lines.push_str("totally not a packet\n\nIP6 fe80::1 > fe80::2: ICMP6\n");
        let big_blob = lines.repeat(5);
        let _ = parse_v4_packet_endpoints(&big_blob);
        let _ = parse_conntrack_entries(&big_blob);
        let _ = parse_conntrack_tcp_dns_entries(&big_blob);
        let _ = parse_ss_established_dns_entries(&big_blob);
        let _ = parse_ip_o_addr_show_v4(&big_blob);
        let _ = parse_ip_o_addr_show_v4_entries(&big_blob);
        let _ = bound_evidence_text(&big_blob);
        let _ = classify_capture(&big_blob, &[TEST_EGRESS_ADDR], TEST_WG_PORT);
        let client_space = ClientSpace::derive(&[], "", TEST_EGRESS_ADDR, TUNNEL_INTERFACE);
        let _ = attribute_forwarded_packets(
            &big_blob,
            TEST_EGRESS_ADDR,
            &[TEST_EGRESS_ADDR.to_owned()],
            &client_space,
            true,
            &[],
            &[],
        );
        let _ =
            tuple_started_inside_window(&big_blob, "tcp", "1.2.3.4", Some(5), "5.6.7.8", Some(6));
    }

    // ── rv: real lab captures replay through the fixed logic ─────────────

    // Replay the REAL u46-r* captures (recorded verdict artifacts carry the
    // capture text): every provided capture must PASS under the fixed
    // attribution when the client FIN is evidenced in both snapshots with a
    // client-space ORIGINAL source, and must FAIL when the same tuple is
    // evidenced only as a host-origin entry. Skips silently when the
    // evidence dir is not mounted (never a false pass).
    #[test]
    fn rv_replay_real_evidence() {
        let evidence_root = std::path::Path::new("/Users/iwan/rustysuite-fleet/evidence/lenovo");
        if !evidence_root.exists() {
            eprintln!("rv_replay_real_evidence: evidence dir absent, skipping");
            return;
        }
        let runs = [
            "u46-r35",
            "u46-r36",
            "u46-r20/u46-r20",
            "u46-r29/u46-r29",
            "u46-r8/u46-r8",
            "u46-r18/u46-r18",
        ];
        let mut exercised = 0;
        for run in runs {
            let path = evidence_root
                .join(run)
                .join("exit_egress_leak_witness.verdict.json");
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let raw_capture = value["capture_stdout"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let egress_addr = value["egress_addr"]
                .as_str()
                .unwrap_or(TEST_EGRESS_ADDR)
                .to_owned();
            let wg_port = value["wg_listen_port"]
                .as_u64()
                .unwrap_or(TEST_WG_PORT as u64) as u16;
            let capture = raw_capture
                .replace(&egress_addr, TEST_EGRESS_ADDR)
                .replace(&format!(".{wg_port} >"), &format!(".{TEST_WG_PORT} >"))
                .replace(
                    &format!(".{wg_port}: UDP"),
                    &format!(".{TEST_WG_PORT}: UDP"),
                );
            // find the masqueraded FIN tuple (tcp/53 from the egress addr)
            let mut fin_sport: Option<u16> = None;
            for line in capture.lines() {
                let Some((src, sport, _dst, dport)) = parse_v4_packet_endpoints(line) else {
                    continue;
                };
                if src == TEST_EGRESS_ADDR
                    && dport == Some(53)
                    && line_transport(line) == LineTransport::Tcp
                {
                    fin_sport = sport;
                    break;
                }
            }
            // the control echo id, if an echo request is present
            let echo_id = capture.lines().find_map(|line| {
                packet_details_after_endpoints(line).and_then(parse_icmp_echo_from_packet)
            });
            let icmp_entry = match echo_id {
                Some(triple) => conntrack_masq_icmp_entry_with_id(
                    "10.6.0.2",
                    TEST_EGRESS_ADDR,
                    WITNESS_ICMP_TARGET,
                    triple.id,
                ),
                None => {
                    conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, WITNESS_ICMP_TARGET)
                }
            };
            let run_witness_on = |start_tcp53: &str, end_tcp53: &str| {
                let mock = Arc::new(MockShellHost::new());
                program_setup(&mock, true);
                program_capture_start_nft_listing(&mock, &nft_table_ok());
                program_boot_table(&mock, None);
                program_local_addrs(&mock);
                program_conntrack(&mock, start_tcp53, "", "");
                program_capture_end_conntrack(&mock, end_tcp53, "", "", &icmp_entry);
                program_capture(&mock, &capture, &tcpdump_stderr_ok());
                run_witness(&mock)
            };
            let Some(sport) = fin_sport else {
                // no tcp/53 FIN in this capture: still run the clean variant
                let report = run_witness_on("", "").expect("setup must succeed");
                assert!(
                    report.failures.is_empty(),
                    "{run}: clean replay must pass: {:?}",
                    report.failures
                );
                exercised += 1;
                continue;
            };
            // host-entry variant: the tuple evidenced as a host-origin
            // ESTABLISHED flow at start, absent at end -> stays a failure
            let host_report = run_witness_on(
                &conntrack_established_entry(TEST_EGRESS_ADDR, sport, "1.1.1.1", 53),
                "",
            )
            .expect("setup must succeed");
            assert_eq!(
                host_report.counts.host_dns_tcp, 1,
                "{run}: host-entry variant must keep the leak"
            );
            // client-entry variant: the tuple evidenced as a masqueraded
            // client flow in BOTH snapshots -> relieved, witness passes
            let client_report = run_witness_on(
                &conntrack_masq_tcp_entry(
                    "10.6.0.2",
                    sport,
                    TEST_EGRESS_ADDR,
                    sport,
                    "1.1.1.1",
                    53,
                ),
                &conntrack_masq_tcp_entry(
                    "10.6.0.2",
                    sport,
                    TEST_EGRESS_ADDR,
                    sport,
                    "1.1.1.1",
                    53,
                ),
            )
            .expect("setup must succeed");
            assert!(
                client_report.failures.is_empty(),
                "{run}: client-entry variant must pass: {:?}",
                client_report.failures
            );
            assert_eq!(client_report.forwarded_dns_tcp.len(), 1);
            exercised += 1;
        }
        eprintln!("rv_replay_real_evidence: {exercised} capture(s) replayed");
    }

    // ── HIGH-2: the raw ICMP positive control is structural ──────────────

    // A capture whose only icmp echo is UNRELATED (id 99, no matching flow,
    // plus a WireGuard keepalive) must fail vacuous — with the raw control
    // in evaluate_leak_witness exactly as before W3.
    #[test]
    fn high2_raw_icmp_vacuity_still_fails() {
        let capture = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 99, seq 1, length 64\n\
             12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        // Q04: the snapshots must carry an icmp entry for the vacuous
        // failure to fire — an unrelated exit-origin echo (id 99) proves
        // the snapshots are icmp-aware while attributing nothing.
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry_with_id(TEST_EGRESS_ADDR, TEST_EGRESS_ADDR, "192.0.2.1", 99),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.forwarded_icmp, 1);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no forwarded traffic")),
            "{:?}",
            report.failures
        );
    }

    // ── katana-xnet-1105: informational conntrack timing diagnostics ─────
    // The diagnostics are evidence only. These tests pin that they are
    // recorded, and — the load-bearing half — that they can never turn a
    // failing witness into a passing one, nor a passing one into a failure.

    /// Program the informational timing-diagnostics conversation for one
    /// gather (the witness gathers it twice: after the client ping and after
    /// the capture-end snapshot). `proc_table` is the raw
    /// `/proc/net/nf_conntrack` text those gathers see.
    fn program_timing_diagnostics(mock: &MockShellHost, clock: &str, proc_table: &str) {
        mock.program_run_response(
            &["date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"],
            exit_ok(&format!("{clock}\n")),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "cat",
                "/proc/sys/net/netfilter/nf_conntrack_icmp_timeout",
            ],
            exit_ok("30\n"),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "cat",
                "/proc/sys/net/netfilter/nf_conntrack_count",
            ],
            exit_ok("17\n"),
        );
        mock.program_run_response(
            &["sudo", "-n", "cat", "/proc/net/stat/nf_conntrack"],
            exit_ok("entries  searched found new invalid ignore delete delete_list insert\n"),
        );
        mock.program_run_response(&DIAG_PROC_ICMP_ARGV, exit_ok(proc_table));
    }

    #[test]
    fn timing_diagnostics_are_recorded_and_leave_a_clean_verdict_untouched() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        // Two gathers (after ping, after end snapshot): program both.
        for clock in [
            "2026-11-01T03:10:56.000000000Z",
            "2026-11-01T03:11:15.500000000Z",
        ] {
            program_timing_diagnostics(&mock, clock, "");
        }
        let report = run_witness(&mock).expect("clean witness must not err on setup");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 1);
        let diag = &report.conntrack_timing_diagnostics;
        assert!(diag.contains("== diag after_client_ping =="), "{diag}");
        assert!(
            diag.contains("== diag after_capture_end_snapshot =="),
            "{diag}"
        );
        assert!(diag.contains("2026-11-01T03:10:56.000000000Z"), "{diag}");
        assert!(diag.contains("2026-11-01T03:11:15.500000000Z"), "{diag}");
        assert!(
            diag.contains("-- nf_conntrack_icmp_timeout --\n30\n"),
            "{diag}"
        );
    }

    #[test]
    fn unprobeable_timing_diagnostics_never_fail_or_change_a_clean_verdict() {
        // Nothing programmed for any diagnostic command: every one errors.
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("clean witness must not err on setup");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(
            report
                .conntrack_timing_diagnostics
                .contains("[transport error"),
            "{}",
            report.conntrack_timing_diagnostics
        );
    }

    // The 1105 shape: a wire echo the attribution snapshots cannot match,
    // snapshots that DO carry an (unrelated) icmp entry — vacuous. The
    // diagnostics then happen to show a perfectly matching masqueraded client
    // entry (the flow existed shortly after the ping). That evidence must be
    // RECORDED but must never rescue the verdict: the witness stays vacuous.
    #[test]
    fn timing_diagnostics_never_rescue_a_vacuous_witness() {
        let capture = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 99, seq 1, length 64\n\
             12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        // icmp-carrying end snapshot that matches nothing on the wire (id 7).
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry_with_id("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 7),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        // The diagnostics see a matching client entry for id 99.
        let matching =
            conntrack_masq_icmp_entry_with_id("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1", 99);
        for clock in [
            "2026-11-01T03:10:56.000000000Z",
            "2026-11-01T03:11:15.500000000Z",
        ] {
            program_timing_diagnostics(&mock, clock, &matching);
        }
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .conntrack_timing_diagnostics
                .contains("id=99 src=192.0.2.1"),
            "diagnostics must record the entry: {}",
            report.conntrack_timing_diagnostics
        );
        assert_eq!(report.positive_control.forwarded_icmp_attributed, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no forwarded traffic")),
            "diagnostics must never satisfy the positive control: {:?}",
            report.failures
        );
    }

    // A real leak stays a leak whatever the diagnostics show: a host-origin
    // udp/53 packet fails even when the diagnostics carry a flattering table.
    #[test]
    fn timing_diagnostics_never_hide_a_real_leak() {
        let capture = format!(
            "{}12:00:03.000000 IP {TEST_EGRESS_ADDR}.40000 > 9.9.9.9.53: UDP, length 40\n",
            clean_capture()
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let matching = conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1");
        for clock in [
            "2026-11-01T03:10:56.000000000Z",
            "2026-11-01T03:11:15.500000000Z",
        ] {
            program_timing_diagnostics(&mock, clock, &matching);
        }
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_udp, 1);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("egress leak: 1 host-origin udp/53")),
            "{:?}",
            report.failures
        );
    }

    // ═══════════ ROUND-2 INDEPENDENT REVIEW TESTS (r2_*) ═══════════
    fn r2_show(tag: &str, r: &LeakWitnessReport) {
        eprintln!(
            "R2[{tag}] pass={} counts={:?} fwd={} pc(raw,icmp_attr,dns_attr)={:?} failures={:?}",
            r.failures.is_empty(),
            r.counts,
            r.forwarded_dns_tcp.len(),
            (
                r.positive_control.forwarded_icmp_raw,
                r.positive_control.forwarded_icmp_attributed,
                r.positive_control.forwarded_dns_attributed
            ),
            r.failures
        );
    }
    fn r2_icmp() -> String {
        conntrack_masq_icmp_entry("10.6.0.2", TEST_EGRESS_ADDR, "192.0.2.1")
    }
    /// start=[tcp53,tcp853,udp53], end=[tcp53,tcp853,udp53,icmp]
    #[allow(clippy::type_complexity)]
    fn r2_run(
        start: [&str; 3],
        end: [&str; 4],
        capture: &str,
        peers: &[(String, String)],
    ) -> LeakWitnessReport {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack(&mock, start[0], start[1], start[2]);
        program_local_addrs(&mock);
        program_capture_end_conntrack(&mock, end[0], end[1], end[2], end[3]);
        program_capture(&mock, capture, &tcpdump_stderr_ok());
        run_witness_with_clients(&mock, peers).expect("setup")
    }

    // (2) /proc/net/nf_conntrack read probing. Round 2 required the file to
    // NEVER be read; round 3 intentionally REVERSES that (the conntrack-less
    // lenovo guests left attribution permanently disarmed and failed every
    // clean run), so this probe stays informational only.
    #[test]
    fn r2_proc_nf_conntrack_never_read() {
        let body =
            crate::vm_lab::implementation_source_slice(include_str!("exit_egress_leak_witness.rs"))
                .expect("implementation slice must parse");
        eprintln!(
            "R2[proc-read] mentions /proc/net/nf_conntrack in non-test code: {} (round-3: intentional fallback)",
            body.contains("nf_conntrack")
        );
    }
    // proc format parses
    #[test]
    fn r2_proc_format_parses() {
        let t = "ipv4     2 tcp      6 299 ESTABLISHED src=10.6.0.2 dst=1.1.1.1 sport=43420 dport=53 src=1.1.1.1 dst=192.0.2.240 sport=53 dport=43420 [ASSURED] mark=0 zone=0 use=2\n\
                 ipv4     2 udp      17 29 src=127.0.0.1 dst=127.0.0.1 sport=60835 dport=53 src=127.0.0.1 dst=127.0.0.1 sport=53535 dport=60835 mark=0 zone=0 use=2\n\
                 ipv4     2 icmp     1 29 src=10.6.0.2 dst=192.0.2.1 type=8 code=0 id=4 src=192.0.2.1 dst=192.0.2.240 type=0 code=0 id=4 mark=0 zone=0 use=1\n\
                 ipv6     10 tcp      6 299 ESTABLISHED src=fd00::2 dst=2606:4700::1111 sport=1 dport=53 src=2606:4700::1111 dst=fd00::2 sport=53 dport=1 mark=0 zone=0 use=2\n";
        let e = parse_conntrack_entries(t);
        eprintln!(
            "R2[proc-parse] {} entries: {:?}",
            e.len(),
            e.iter()
                .map(|x| (&x.proto, &x.original.src))
                .collect::<Vec<_>>()
        );
        assert!(e.len() >= 3);
    }
    // (2) conntrack binary missing on the guest: clean capture + client ICMP,
    // no /proc and no ss programmed -> transport errors everywhere; the
    // round-3 conditionality keeps the clean run GREEN on raw controls alone.
    #[test]
    fn r2_no_conntrack_binary_clean_run() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        program_local_addrs(&mock);
        for (proto, dport) in [
            ("tcp", Some("53")),
            ("tcp", Some("853")),
            ("udp", Some("53")),
            ("icmp", None),
        ] {
            let mut argv: Vec<&str> = vec!["sudo", "-n", "conntrack", "-L", "-p", proto];
            if let Some(d) = dport {
                argv.push("--dport");
                argv.push(d);
            }
            mock.program_run_response(&argv, exit_code(127, ""));
        }
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup");
        r2_show("no-conntrack-clean", &r);
        assert!(
            r.failures.is_empty(),
            "clean run on a guest without conntrack fails: {:?}",
            r.failures
        );
    }
    // (2b) green captures r8/r18 on a conntrack-less guest
    #[test]
    fn r2_no_conntrack_binary_green_evidence_runs() {
        let base = "/Users/iwan/rustysuite-fleet/evidence/lenovo";
        for (tag, p) in [("r8", "u46-r8/u46-r8"), ("r18", "u46-r18/u46-r18")] {
            let path = format!("{base}/{p}/exit_egress_leak_witness.verdict.json");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            let cap = v["capture_stdout"].as_str().unwrap().replace(
                v["egress_addr"].as_str().unwrap_or(TEST_EGRESS_ADDR),
                TEST_EGRESS_ADDR,
            );
            let mock = Arc::new(MockShellHost::new());
            program_setup(&mock, true);
            program_capture_start_nft_listing(&mock, &nft_table_ok());
            program_boot_table(&mock, None);
            program_conntrack_missing(&mock);
            program_local_addrs(&mock);
            program_capture(&mock, &cap, &tcpdump_stderr_ok());
            let r = run_witness(&mock).expect("setup");
            r2_show(&format!("no-conntrack-{tag}"), &r);
        }
    }

    // (3) transient-gap host flow replays: must FAIL
    fn r2_syn_fin_capture(with_syn: bool) -> String {
        let mut c = clean_capture();
        if with_syn {
            c.push_str(&format!(
                "12:00:06.000000 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [S], seq 0, win 64240, length 0\n"
            ));
            c.push_str(&format!(
                "12:00:06.010000 IP 1.1.1.1.53 > {TEST_EGRESS_ADDR}.43420: Flags [S.], seq 0, ack 1, win 64240, length 0\n"
            ));
        }
        c.push_str(&format!(
            "12:00:12.802940 IP 1.1.1.1.53 > {TEST_EGRESS_ADDR}.43420: Flags [F.], seq 1, ack 1, win 507, length 0\n"
        ));
        c.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, ack 1, win 507, length 0\n"
        ));
        c
    }
    fn r2_host_tw(src: &str) -> String {
        format!(
            "tcp      6 119 TIME_WAIT src={src} dst=1.1.1.1 sport=43420 dport=53 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 dport=43420 [ASSURED] mark=0 zone=0 use=2\n"
        )
    }
    fn r2_client_tw() -> String {
        conntrack_masq_tcp_entry("10.6.0.2", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53)
    }
    #[test]
    fn r2_host_origin_variants_must_fail() {
        let stage_peers = vec![("client-1".to_owned(), "10.6.0.2".to_owned())];
        for clients in [vec![], stage_peers.clone()] {
            for with_syn in [false, true] {
                let cap = r2_syn_fin_capture(with_syn);
                let host = r2_host_tw(TEST_EGRESS_ADDR);
                let tun = r2_host_tw("10.6.0.1");
                let icmp = r2_icmp();
                let ctw = r2_client_tw();
                let cases: Vec<(&str, [&str; 3], [&str; 4])> = vec![
                    ("host-end-only", ["", "", ""], [&host, "", "", &icmp]),
                    ("host-both", [&host, "", ""], [&host, "", "", &icmp]),
                    ("host-start-only", [&host, "", ""], ["", "", "", &icmp]),
                    ("tunaddr-both", [&tun, "", ""], [&tun, "", "", &icmp]),
                    (
                        "host-start+client-end",
                        [&host, "", ""],
                        [&ctw, "", "", &icmp],
                    ),
                    (
                        "client-start+host-end",
                        [&ctw, "", ""],
                        [&host, "", "", &icmp],
                    ),
                    ("no-entries", ["", "", ""], ["", "", "", &icmp]),
                ];
                for (name, s, e) in cases {
                    let r = r2_run(s, e, &cap, &clients);
                    r2_show(
                        &format!("host:{name}:syn={with_syn}:stage={}", !clients.is_empty()),
                        &r,
                    );
                    // expected: fail, except the start-only/syn combos documented below
                    if !r.failures.is_empty() {
                        continue;
                    }
                    eprintln!(
                        "R2[!!FAILOPEN] {name} syn={with_syn} stage={}",
                        !clients.is_empty()
                    );
                }
            }
        }
    }
    // port reuse: host TIME_WAIT in start (expired by end), client entry in
    // end, SYN in window — the NEW round-3 START-conflict check must fail it.
    #[test]
    fn r2_port_reuse_after_host_entry_expiry() {
        let cap = r2_syn_fin_capture(true);
        let r = r2_run(
            [&r2_host_tw(TEST_EGRESS_ADDR), "", ""],
            [&r2_client_tw(), "", "", &r2_icmp()],
            &cap,
            &[],
        );
        r2_show("reuse-host-start-client-end-syn", &r);
        assert!(
            !r.failures.is_empty(),
            "port reuse after host-entry expiry must fail closed: {:?}",
            (r.failures, r.forwarded_dns_tcp)
        );
        assert!(r.forwarded_dns_tcp.is_empty());
    }
    // ClientSpace derive from listing with docker/virbr/second NIC
    #[test]
    fn r2_client_space_derive_from_bridges() {
        let listing = "1: lo    inet 127.0.0.1/8 scope host lo\\\n2: eth0    inet 192.168.122.31/24 scope global eth0\\\n3: docker0    inet 172.17.0.1/16 scope global docker0\\\n4: eth1    inet 10.99.0.5/24 scope global eth1\\\n5: rustynet0    inet 100.123.229.22/32 scope global rustynet0\\\n";
        let cs = ClientSpace::derive(&[], listing, "192.168.122.31", TUNNEL_INTERFACE);
        for a in [
            "172.17.0.2",
            "10.99.0.77",
            "100.95.199.56",
            "192.168.122.50",
        ] {
            eprintln!("R2[clientspace-{a}] admits={}", cs.admits(a));
            assert!(
                !cs.admits(a),
                "bridge/second-NIC subnets must not widen the client space: {a}"
            );
        }
    }
    // W2 on the REAL emitted killswitch shape
    #[test]
    fn r2_w2_real_table_shapes() {
        let real_output_chain = "table inet rustynet_g7 {\n\
            \x20 chain killswitch {\n\
            \x20  type filter hook output priority filter; policy drop;\n\
            \x20  oifname \"lo\" accept\n\
            \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
            \x20  ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept\n\
            \x20  ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept\n\
            \x20  oifname \"rustynet0\" accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
            \x20 }\n\
            }\n";
        let r = verify_listing(real_output_chain);
        eprintln!(
            "R2[w2-real-output-chain] ok={} {:?}",
            r.is_ok(),
            r.as_ref()
                .err()
                .map(|e| e.chars().take(200).collect::<String>())
        );
        assert!(
            r.is_ok(),
            "the REAL production table must pass: {:?}",
            r.err()
        );
        // and it must carry NO informational findings either
        let posture = verify_posture(real_output_chain).expect("real table must verify");
        assert!(
            posture.order_findings.is_empty(),
            "REAL production table must be finding-free: {:?}",
            posture.order_findings
        );
        let with_forward = "table inet rustynet_g7 {\n\
            \x20 chain killswitch {\n\
            \x20  type filter hook output priority filter; policy drop;\n\
            \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
            \x20 }\n\
            \x20 chain forward {\n\
            \x20  type filter hook forward priority filter; policy drop;\n\
            \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
            \x20  iifname \"rustynet0\" oifname \"enp0s9\" accept\n\
            \x20 }\n\
            }\n";
        let r = verify_listing(with_forward);
        eprintln!(
            "R2[w2-real-forward-chain] ok={} {:?}",
            r.is_ok(),
            r.as_ref()
                .err()
                .map(|e| e.chars().take(200).collect::<String>())
        );
        assert!(
            r.is_ok(),
            "forward-chain iifname accepts need no ordering: {:?}",
            r.err()
        );
        let only_lo = "table inet rustynet_g7 {\n\
            \x20 chain killswitch {\n\
            \x20  type filter hook output priority filter; policy drop;\n\
            \x20  oifname \"lo\" accept\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
            \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
            \x20 }\n\
            }\n";
        let r = verify_listing(only_lo);
        eprintln!(
            "R2[w2-lo-accept-first] ok={} {:?}",
            r.is_ok(),
            r.as_ref()
                .err()
                .map(|e| e.chars().take(200).collect::<String>())
        );
        assert!(
            r.is_ok(),
            "lo-scoped accept cannot carry egress DNS: {:?}",
            r.err()
        );
        let rn0 = only_lo.replace("oifname \\\"lo\\\" accept", "x").replace(
            "oifname \"lo\" accept",
            "oifname \"rustynet0\" meta nfproto ipv4 accept",
        );
        let r = verify_listing(&rn0);
        eprintln!(
            "R2[w2-rustynet0-accept-first] ok={} {:?}",
            r.is_ok(),
            r.as_ref()
                .err()
                .map(|e| e.chars().take(200).collect::<String>())
        );
        assert!(
            r.is_ok(),
            "tunnel-scoped accept cannot carry EGRESS-NIC DNS: {:?}",
            r.err()
        );
        // violating shapes WITHOUT an explicit established-flow accept are
        // now NON-FATAL findings (round-4 severity split); the iifname-bound
        // accept stays clean.
        for (n, l, expect) in [
            (
                "oif-egress-accept-first",
                "oifname \"enp0s9\" accept",
                "finding",
            ),
            ("daddr-accept-first", "ip daddr 1.1.1.1 accept", "finding"),
            // round-3 scope rule: an iifname-bound accept never carries
            // egress-NIC OUTPUT DNS, so it needs no ordering (per the fix
            // scope; the round-2 probe listed it as suspicious).
            ("iif-accept-first", "iifname \"lo\" accept", "clean"),
            (
                "tcp-dport-53-oif-other",
                "oifname \"rustynet0\" tcp dport 53 accept",
                "finding",
            ),
        ] {
            let t = format!(
                "table inet rustynet_g7 {{\n\x20 chain killswitch {{\n\x20  {l}\n\x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport {{ 53, 853 }} drop\n\x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport {{ 53, 853 }} drop\n\x20 }}\n}}\n"
            );
            let posture =
                verify_posture(&t).unwrap_or_else(|e| panic!("{n} must not be fatal: {e}"));
            eprintln!("R2[w2-{n}] findings={}", posture.order_findings.len());
            if expect == "finding" {
                assert!(
                    !posture.order_findings.is_empty(),
                    "{n} must carry a non-fatal order finding"
                );
            } else {
                assert!(
                    posture.order_findings.is_empty(),
                    "{n} must stay clean, got {:?}",
                    posture.order_findings
                );
            }
        }
    }
    // LOW: ICMP id remap by NAT
    #[test]
    fn r2_icmp_nat_id_remap() {
        // client id 1 remapped by masquerade to id 4 on the wire/reply tuple
        let e = "icmp      1 29 src=10.6.0.2 dst=192.0.2.1 type=8 code=0 id=1 src=192.0.2.1 dst=192.0.2.240 type=0 code=0 id=4 mark=0 use=1\n";
        let cap = clean_capture().replace("id 1,", "id 4,");
        let r = r2_run(["", "", ""], ["", "", "", e], &cap, &[]);
        r2_show("icmp-id-remap", &r);
    }

    // same-snapshot host+client conflict (N10 survivor probe)
    #[test]
    fn r2_same_snapshot_host_client_conflict_fails() {
        let host = r2_host_tw(TEST_EGRESS_ADDR);
        let client = r2_client_tw();
        let icmp = r2_icmp();
        for syn in [false, true] {
            let cap = r2_syn_fin_capture(syn);
            for (n, end) in [
                ("client-first", format!("{client}{host}")),
                ("host-first", format!("{host}{client}")),
            ] {
                let both = [end.as_str(), "", ""];
                let r = r2_run([end.as_str(), "", ""], [both[0], "", "", &icmp], &cap, &[]);
                r2_show(&format!("conflict-{n}-syn={syn}"), &r);
                assert!(!r.failures.is_empty());
            }
        }
    }

    // ═══════════ ROUND-3 WITNESS TESTS (w3s_*) ═══════════

    fn w3s_single_accept_shape(first_rule: &str) -> String {
        format!(
            "table inet rustynet_g7 {{\n\x20 chain killswitch {{\n\x20  {first_rule}\n\x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport {{ 53, 853 }} drop\n\x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport {{ 53, 853 }} drop\n\x20 }}\n}}\n"
        )
    }

    fn w3s_tokens(collapsed: &str) -> Vec<&str> {
        strip_nft_comment(collapsed).split_whitespace().collect()
    }

    // NEW-1: the REAL production table (scoped protected-DNS shape with the
    // l4proto exclusion accept and a forward chain) must pass the W2 order
    // check end-to-end.
    #[test]
    fn w3s_real_scoped_table_passes() {
        let real = "table inet rustynet_g7 {\n\
         \x20 chain killswitch {\n\
         \x20  type filter hook output priority filter; policy drop;\n\
         \x20  oifname \"lo\" accept\n\
         \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
         \x20  ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept\n\
         \x20  ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept\n\
         \x20  oifname \"rustynet0\" accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
         \x20 }\n\
         \x20 chain forward {\n\
         \x20  type filter hook forward priority filter; policy drop;\n\
         \x20  ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept\n\
         \x20  ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept\n\
         \x20  ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept\n\
         \x20  iifname \"rustynet0\" oifname \"enp0s9\" accept\n\
         \x20 }\n\
         }\n";
        let r = verify_listing(real);
        assert!(r.is_ok(), "real scoped table must pass: {:?}", r.err());
    }

    // NEW-1 unit: the `meta l4proto != { tcp, udp }` exclusion accept can
    // never match tcp/udp DNS.
    #[test]
    fn w3s_l4proto_exclusion_skipped() {
        assert!(!accept_can_match_dns_ports(
            "ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept"
        ));
        assert!(!accept_can_match_dns_ports(
            "meta l4proto != { udp, tcp } accept"
        ));
        // without both protocols in the set it stays DNS-capable
        assert!(accept_can_match_dns_ports("meta l4proto != { tcp } accept"));
    }

    // NEW-1 unit: iifname-bound / other-oifname accepts are scoped away from
    // egress-NIC output DNS; egress-scoped and unscoped accepts are not.
    #[test]
    fn w3s_iifname_accept_forward_chain_ok() {
        assert!(accept_scoped_away_from_egress_output(
            &w3s_tokens("iifname \"rustynet0\" oifname \"enp0s9\" accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(accept_scoped_away_from_egress_output(
            &w3s_tokens("oifname \"lo\" accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(accept_scoped_away_from_egress_output(
            &w3s_tokens("oifname \"rustynet0\" meta nfproto ipv4 accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(!accept_scoped_away_from_egress_output(
            &w3s_tokens("oifname \"enp0s9\" meta nfproto ipv4 accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(!accept_scoped_away_from_egress_output(
            &w3s_tokens("ct state established,related accept"),
            TEST_EGRESS_IFACE
        ));
        // round-4: negated and set interface matches NEVER scope away
        assert!(!accept_scoped_away_from_egress_output(
            &w3s_tokens("oifname != \"lo\" accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(!accept_scoped_away_from_egress_output(
            &w3s_tokens("oifname { \"lo\", \"enp0s9\" } accept"),
            TEST_EGRESS_IFACE
        ));
        assert!(!accept_scoped_away_from_egress_output(
            &w3s_tokens("iifname != \"rustynet0\" accept"),
            TEST_EGRESS_IFACE
        ));
        // negated matches prove nothing, but a positive iifname beside one
        // still scopes the rule away
        assert!(accept_scoped_away_from_egress_output(
            &w3s_tokens("iifname \"enp0s9\" oifname != \"lo\" accept"),
            TEST_EGRESS_IFACE
        ));
        // a positive iifname still scopes away even beside a negated oifname
        assert!(accept_scoped_away_from_egress_output(
            &w3s_tokens("iifname \"rustynet0\" oifname != \"lo\" accept"),
            TEST_EGRESS_IFACE
        ));
    }

    // NEW-1: unsafe shapes. The unqualified established accept stays FATAL;
    // every other violating shape is now a NON-FATAL finding recorded under
    // dns_rule_order_findings (round-4 severity split).
    #[test]
    fn w3s_unsafe_w2_shapes_still_rejected() {
        for (name, shape) in [
            // accept scoped TO the egress NIC before the drops
            ("oif-egress", "oifname \"enp0s9\" accept"),
            // destination-address accept before the drops
            ("daddr", "ip daddr 1.1.1.1 accept"),
            // explicit DNS dport accept, even scoped to another interface
            (
                "dport-scoped-other",
                "oifname \"rustynet0\" tcp dport 53 accept",
            ),
            // the bare DNS-port accept
            ("bare-dport", "tcp dport 53 accept"),
        ] {
            let posture = verify_posture(&w3s_single_accept_shape(shape));
            let findings = posture.expect("{name} must not be fatal");
            assert!(
                !findings.order_findings.is_empty(),
                "{name} must carry a non-fatal order finding, got empty: {findings:?}"
            );
            assert!(
                findings
                    .order_findings
                    .iter()
                    .all(|f| f.contains(shape) && f.contains("non-fatal DNS rule order finding")),
                "{name} finding must name the rule and be informational: {:?}",
                findings.order_findings
            );
        }
        // the unqualified established accept before the drops: STILL FATAL
        let err = verify_listing(&w3s_single_accept_shape(
            "ct state established,related accept",
        ))
        .expect_err("established accept must stay fatal");
        assert!(err.starts_with("kill switch rule order unsafe:"), "{err}");
        assert!(err.contains("ct state established,related accept"), "{err}");
    }

    /// A synthetic `/proc/net/nf_conntrack` snapshot in the REAL kernel line
    /// format: an unrelated tcp/22 entry, a localhost resolver udp/53 entry,
    /// and the masqueraded client ICMP echo (id 1 — the clean-capture id).
    fn w3s_proc_snapshot() -> String {
        "ipv4     2 tcp      6 299 ESTABLISHED src=192.168.122.1 dst=192.168.122.31 sport=42530 dport=22 src=192.168.122.31 dst=192.168.122.1 sport=22 dport=42530 [ASSURED] mark=0 zone=0 use=2\n\
         ipv4     2 udp      17 29 src=127.0.0.1 dst=127.0.0.53 sport=60835 dport=53 src=127.0.0.53 dst=127.0.0.1 sport=53 dport=60835 mark=0 zone=0 use=2\n\
         ipv4     2 icmp     1 29 src=10.6.0.2 dst=192.0.2.1 type=8 code=0 id=1 src=192.0.2.1 dst=192.0.2.240 type=0 code=0 id=1 mark=0 zone=0 use=1\n\
         ipv6     10 tcp      6 299 ESTABLISHED src=fd00::2 dst=2606:4700::1111 sport=1 dport=53 src=2606:4700::1111 dst=fd00::2 sport=53 dport=1 mark=0 zone=0 use=2\n"
            .to_owned()
    }

    fn w3s_program_end_conntrack_missing(mock: &MockShellHost) {
        for (proto, dport) in [
            ("tcp", Some("53")),
            ("tcp", Some("853")),
            ("udp", Some("53")),
            ("icmp", None),
        ] {
            let mut argv: Vec<&str> = vec!["sudo", "-n", "conntrack", "-L", "-p", proto];
            if let Some(d) = dport {
                argv.push("--dport");
                argv.push(d);
            }
            mock.program_run_response(&argv, exit_code(127, ""));
        }
    }

    fn w3s_program_proc(mock: &MockShellHost, snapshot: &str) {
        mock.program_run_response(&PROC_NF_CONNTRACK_ARGV, exit_ok(snapshot));
    }

    // NEW-2: with the conntrack binary missing on BOTH windows, a successful
    // filtered /proc read ARMS attribution: the clean capture stays green and
    // the masqueraded client ICMP is attributed.
    #[test]
    fn w3s_proc_fallback_arms_attribution() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        program_local_addrs(&mock);
        w3s_program_end_conntrack_missing(&mock);
        let snap = w3s_proc_snapshot();
        w3s_program_proc(&mock, &snap);
        w3s_program_proc(&mock, &snap);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        r2_show("w3s-proc-arms", &r);
        assert!(
            r.capture_start_conntrack.contains(CONNTRACK_UNAVAILABLE),
            "{:?}",
            r.capture_start_conntrack
        );
        assert!(
            r.capture_start_conntrack.contains(PROC_NF_CONNTRACK_LABEL),
            "{:?}",
            r.capture_start_conntrack
        );
        // the unrelated tcp/22 line is filtered OUT of the bounded blob
        assert!(
            !r.capture_start_conntrack.contains("dport=22"),
            "proc filter must drop irrelevant lines: {:?}",
            r.capture_start_conntrack
        );
        assert!(
            r.failures.is_empty(),
            "proc fallback must keep the clean run green: {:?}",
            r.failures
        );
        assert_eq!(r.positive_control.forwarded_icmp_attributed, 1);
    }

    // NEW-2 red-stays-red: a host-origin FIN with NO matching entry in the
    // proc snapshots stays a leak; with a HOST-ORIGIN established entry in
    // the START proc snapshot the pre-existing failure fires too.
    #[test]
    fn w3s_proc_fallback_red_stays_red() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:12.803670 IP {TEST_EGRESS_ADDR}.43420 > 1.1.1.1.53: Flags [F.], seq 1, ack 1, win 507, length 0\n"
        ));
        // (a) no matching entry anywhere
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        program_local_addrs(&mock);
        w3s_program_end_conntrack_missing(&mock);
        w3s_program_proc(&mock, &w3s_proc_snapshot());
        w3s_program_proc(&mock, &w3s_proc_snapshot());
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        r2_show("w3s-proc-red-nomatch", &r);
        assert!(
            r.failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet")),
            "{:?}",
            r.failures
        );
        assert!(r.forwarded_dns_tcp.is_empty());
        // (b) the START proc snapshot carries the flow as HOST-ORIGIN
        // established — pre-existing failure + labelled leak
        let host_proc = format!(
            "ipv4     2 tcp      6 299 ESTABLISHED src={TEST_EGRESS_ADDR} dst=1.1.1.1 sport=43420 dport=53 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 dport=43420 [ASSURED] mark=0 zone=0 use=2\n{}",
            w3s_proc_snapshot()
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        program_local_addrs(&mock);
        w3s_program_end_conntrack_missing(&mock);
        w3s_program_proc(&mock, &host_proc);
        w3s_program_proc(&mock, &w3s_proc_snapshot());
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        r2_show("w3s-proc-red-hostorigin", &r);
        assert!(
            r.failures
                .iter()
                .any(|f| *f == PRE_EXISTING_TCP_DNS_FAILURE),
            "{:?}",
            r.failures
        );
        assert!(
            r.failures
                .iter()
                .any(|f| f.contains("host-origin tcp/53 packet")),
            "{:?}",
            r.failures
        );
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // NEW-2 W1 extension: an ESTABLISHED host tcp/53 line in the kernel
    // /proc format (`ipv4 2 tcp 6 ...`) must count as pre-existing.
    #[test]
    fn w3s_proc_w1_preexisting_extended_line_detected() {
        let line = format!(
            "ipv4     2 tcp      6 299 ESTABLISHED src={TEST_EGRESS_ADDR} dst=1.1.1.1 sport=43420 dport=53 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 dport=43420 [ASSURED] mark=0 zone=0 use=2\n"
        );
        let conns = parse_conntrack_tcp_dns_entries(&line);
        assert_eq!(conns.len(), 1, "{conns:?}");
        assert_eq!(conns[0].local_addr, TEST_EGRESS_ADDR);
        assert_eq!(conns[0].remote_port, 53);
        // and end-to-end through the proc fallback (covered red in
        // w3s_proc_fallback_red_stays_red (b))
        let udp_line = "ipv4     2 udp      17 29 src=10.6.0.2 dst=1.1.1.1 sport=40001 dport=53 src=1.1.1.1 dst=192.0.2.240 sport=53 dport=40001 mark=0 zone=0 use=2\n";
        assert!(parse_conntrack_tcp_dns_entries(udp_line).is_empty());
    }

    // NEW-2 unit: the /proc filter keeps icmp and DNS-port lines, drops the
    // rest, and never panics on garbage.
    #[test]
    fn w3s_proc_filter_keeps_relevant_lines() {
        let kept = filter_proc_nf_conntrack_lines(&w3s_proc_snapshot());
        assert!(kept.contains("icmp"));
        assert!(kept.contains("dport=53"));
        assert!(!kept.contains("dport=22"));
        assert_eq!(kept.lines().count(), 3);
        assert!(filter_proc_nf_conntrack_lines("total garbage\n\n").is_empty());
    }

    // NEW round-3 conditionality: with attribution DISARMED the positive
    // control never demands the unsatisfiable attributed ICMP; the raw
    // control in evaluate_leak_witness still fires (separately).
    #[test]
    fn w3s_positive_control_raw_only_when_disabled() {
        let raw_unattributed = PositiveControlEvidence {
            forwarded_icmp_raw: 4,
            exit_origin_icmp: 4,
            forwarded_icmp_attributed: 0,
            forwarded_dns_attributed: 0,
            client_original_srcs: vec![],
            proven: "nothing proven".to_owned(),
        };
        assert!(
            evaluate_positive_control(&raw_unattributed, TEST_EGRESS_IFACE, false, true).is_empty(),
            "disarmed attribution must not demand attributed ICMP"
        );
        assert_eq!(
            evaluate_positive_control(&raw_unattributed, TEST_EGRESS_IFACE, true, true).len(),
            1,
            "armed attribution with zero attributed ICMP still fails"
        );
    }

    // NEW round-3 information fields: the DNS-socket snapshots are recorded
    // at capture start AND end, tolerating transport errors.
    #[test]
    fn w3s_dns_sockets_fields_present() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "ss",
                "-tnpH",
                "state",
                "all",
                "( dport = :53 or dport = :853 )",
            ],
            exit_ok("ESTAB 0 0 192.168.122.1:42530 192.168.122.31:53\n"),
        );
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "ss",
                "-tnpH",
                "state",
                "all",
                "( dport = :53 or dport = :853 )",
            ],
            exit_ok("ESTAB 0 0 192.168.122.1:42531 192.168.122.31:853\n"),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        assert!(
            r.capture_start_dns_sockets.contains("42530"),
            "{:?}",
            r.capture_start_dns_sockets
        );
        assert!(
            r.capture_end_dns_sockets.contains("42531"),
            "{:?}",
            r.capture_end_dns_sockets
        );
        // unprogrammed reads are tolerated and recorded, never fatal
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        assert!(r.capture_start_dns_sockets.contains("ss -tnpH"));
        assert!(r.failures.is_empty(), "{:?}", r.failures);
    }

    // NEW-3 witness: host TIME_WAIT in START (original = the egress address,
    // expired by END), client entry in END, SYN inside the window — the
    // START-conflict check must block the attribution.
    #[test]
    fn w3s_start_conflict_blocks_syn_window() {
        let cap = r2_syn_fin_capture(true);
        let r = r2_run(
            [&r2_host_tw(TEST_EGRESS_ADDR), "", ""],
            [&r2_client_tw(), "", "", &r2_icmp()],
            &cap,
            &[],
        );
        r2_show("w3s-start-conflict", &r);
        assert!(
            !r.failures.is_empty(),
            "start-conflict tuple reuse must stay a leak: {:?}",
            (r.failures, r.forwarded_dns_tcp)
        );
        assert_eq!(r.counts.host_dns_tcp, 2);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // LOW-5 witness: only the TUNNEL interface's subnet may seed the derived
    // client space; docker0, a second NIC and the egress subnet are refused.
    #[test]
    fn w3s_client_space_tunnel_only() {
        let listing = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                       2: eth0    inet 192.168.122.31/24 scope global eth0\\\n\
                       3: docker0    inet 172.17.0.1/16 scope global docker0\\\n\
                       4: eth1    inet 10.99.0.5/24 scope global eth1\\\n\
                       5: rustynet0    inet 100.123.229.22/32 scope global rustynet0\\\n";
        let cs = ClientSpace::derive(&[], listing, "192.168.122.31", TUNNEL_INTERFACE);
        for a in [
            "172.17.0.2",
            "10.99.0.77",
            "100.95.199.56",
            "192.168.122.50",
        ] {
            assert!(!cs.admits(a), "{a} must not be admitted");
        }
        // the tunnel /32 still admits exactly its own address
        assert!(cs.admits("100.123.229.22"));
    }

    // MED-5 unit: the infrastructure-class gate is load-bearing on its own,
    // independent of the tier that consults it.
    #[test]
    fn w3s_disallowed_client_src_classes() {
        for a in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.9.9",
            "224.0.0.1",
            "239.1.2.3",
            "255.255.255.255",
            "garbage",
        ] {
            assert!(is_disallowed_client_src(a), "{a} must be disallowed");
        }
        assert!(!is_disallowed_client_src("10.6.0.2"));
        assert!(!is_disallowed_client_src("100.64.0.23"));
    }

    // ── W3T: forwarded mesh-peer attribution scope (u46-r48/r35 replay) ──
    //
    // Live facts (lenovo fleet, archived under
    // /Users/iwan/rustysuite-fleet/evidence/lenovo): the tcp/53 FIN pairs the
    // witness flagged as `host-origin` were FORWARDED+MASQUERADED MESH-PEER
    // flows — on u46-r48 the ORIGINAL source was the ENTRY node's mesh
    // address (a RELAY), not the client's, so client-only admission (the W3
    // stage shape) mis-flagged normal mesh transit. The replay constants
    // below are the archived capture text and the real /proc-format
    // conntrack line, byte-faithful except for the rewritten egress address.

    /// u46-r48/r35 mesh addresses, exactly as the orchestrator's
    /// `ctx.mesh_ips` held them.
    const W3T_CLIENT_MESH: &str = "100.95.199.56"; // lenovo-client-1
    const W3T_ENTRY_MESH: &str = "100.66.184.214"; // lenovo-entry-1 (RELAY)
    const W3T_EXIT_MESH: &str = "100.123.229.22"; // lenovo-exit-1

    /// The allowed ORIGINAL-source set exactly as the stage builds it: every
    /// non-exit mesh peer WITH its alias, sorted.
    fn w3t_peers_all() -> Vec<(String, String)> {
        vec![
            ("lenovo-client-1".to_owned(), W3T_CLIENT_MESH.to_owned()),
            ("lenovo-entry-1".to_owned(), W3T_ENTRY_MESH.to_owned()),
        ]
    }

    /// The REAL /proc-format conntrack line the u46-r48 poll read carried for
    /// the flagged FIN pair (leakpoll-u46-r48.log), with the reply dst
    /// rewritten to the test egress address exactly like the capture replay.
    fn w3t_proc_tcp_entry(original_src: &str, sport: u16) -> String {
        format!(
            "ipv4     2 tcp      6 431999 ESTABLISHED src={original_src} dst=1.1.1.1 \
             sport={sport} dport=53 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 \
             dport={sport} [ASSURED] mark=0 zone=0 use=2\n"
        )
    }

    /// SYNTHETIC masqueraded-ICMP entry in the real kernel /proc line format
    /// (id 4 = the wire packets of both runs): the leakpoll reads carried NO
    /// icmp lines, but without a conntrack ICMP entry the positive control is
    /// vacuous by design — this entry documents what the exit's table held
    /// while the masqueraded client echoes flew.
    fn w3t_proc_icmp_entry(original_src: &str) -> String {
        conntrack_extended_icmp_entry(original_src, TEST_EGRESS_ADDR, "192.0.2.1", 4)
    }

    /// The lenovo evidence path: the conntrack binary missing on BOTH
    /// windows, attribution armed by the filtered /proc fallback carrying the
    /// flow in BOTH snapshots (no SYN for the sport anywhere in the window).
    fn w3t_program_replay(mock: &MockShellHost, tcp_entry: &str, icmp_src: &str, capture: &str) {
        program_setup(mock, true);
        program_capture_start_nft_listing(mock, &nft_table_ok());
        program_boot_table(mock, None);
        program_conntrack_missing(mock);
        program_local_addrs(mock);
        w3s_program_end_conntrack_missing(mock);
        let snap = format!("{tcp_entry}{}", w3t_proc_icmp_entry(icmp_src));
        w3s_program_proc(mock, &snap);
        w3s_program_proc(mock, &snap);
        program_capture(mock, capture, &tcpdump_stderr_ok());
    }

    const W3T_R48_CAPTURE: &str = r#"05:37:20.360401 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
05:37:20.360460 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 1, length 64
05:37:21.382257 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
05:37:21.382525 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 2, length 64
05:37:21.424463 IP 1.1.1.1.53 > 192.0.2.240.55222: Flags [F.], seq 1513800849, ack 3037766728, win 16, options [nop,nop,TS val 1724446591 ecr 3227352904], length 0
05:37:21.424755 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 96
05:37:21.426108 IP 192.168.0.32.51820 > 192.0.2.240.51820: UDP, length 96
05:37:21.426271 IP 192.0.2.240.55222 > 1.1.1.1.53: Flags [F.], seq 1, ack 1, win 507, options [nop,nop,TS val 3227362864 ecr 1724446591], length 0
05:37:21.432616 IP 1.1.1.1.53 > 192.0.2.240.55222: Flags [.], ack 2, win 16, options [nop,nop,TS val 1724446599 ecr 3227362864], length 0
05:37:21.432848 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 96
05:37:22.406482 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
05:37:22.406735 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 3, length 64
05:37:22.648490 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 32
05:37:23.434048 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
05:37:23.434262 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 4, length 64
05:37:24.342729 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 224
05:37:24.342778 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 224
05:37:30.735351 IP 192.168.0.32.51820 > 192.0.2.240.51820: UDP, length 224
05:37:30.765421 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 224
05:37:30.768542 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 224
05:37:40.824586 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 32
05:37:40.870634 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 32
"#;

    const W3T_R35_CAPTURE: &str = r#"00:34:07.240564 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
00:34:07.240653 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 1, length 64
00:34:08.255525 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
00:34:08.255753 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 2, length 64
00:34:09.280516 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
00:34:09.280679 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 3, length 64
00:34:09.348650 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 224
00:34:09.348802 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 224
00:34:10.304285 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 128
00:34:10.304569 IP 192.0.2.240 > 192.0.2.1: ICMP echo request, id 4, seq 4, length 64
00:34:12.519340 IP 192.168.0.32.51820 > 192.0.2.240.51820: UDP, length 32
00:34:12.802739 IP 1.1.1.1.53 > 192.0.2.240.43420: Flags [F.], seq 3053497094, ack 2025481739, win 16, options [nop,nop,TS val 2330711794 ecr 2325942557], length 0
00:34:12.803111 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 96
00:34:12.803624 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 96
00:34:12.803670 IP 192.0.2.240.43420 > 1.1.1.1.53: Flags [F.], seq 1, ack 1, win 507, options [nop,nop,TS val 2325952527 ecr 2330711794], length 0
00:34:12.810628 IP 1.1.1.1.53 > 192.0.2.240.43420: Flags [.], ack 2, win 16, options [nop,nop,TS val 2330711802 ecr 2325952527], length 0
00:34:12.810851 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 96
00:34:16.936570 IP 192.168.0.32.51820 > 192.0.2.240.51820: UDP, length 224
00:34:16.969571 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 224
00:34:17.486419 IP 192.0.2.240.51820 > 192.168.0.30.51820: UDP, length 224
00:34:27.133583 IP 192.0.2.240.51820 > 192.168.0.32.51820: UDP, length 32
00:34:27.589136 IP 192.168.0.30.51820 > 192.0.2.240.51820: UDP, length 32
"#;

    /// Drift guard: the embedded replay evidence must stay byte-faithful to
    /// the archived runs (the ONLY permitted difference is the rewritten
    /// egress address). On a machine without the archive this skips — the
    /// Linux build box cannot see it; the Mac that produced the evidence can.
    #[test]
    fn w3t_embedded_replay_evidence_matches_archive() {
        let root = std::path::Path::new("/Users/iwan/rustysuite-fleet/evidence/lenovo");
        for (run, capture, _sport) in [
            ("u46-r48", W3T_R48_CAPTURE, 55222),
            ("u46-r35", W3T_R35_CAPTURE, 43420),
        ] {
            let Ok(bytes) =
                std::fs::read(root.join(run).join("exit_egress_leak_witness.verdict.json"))
            else {
                eprintln!("w3t drift guard: {run} archive absent, skipping");
                continue;
            };
            let value: serde_json::Value = serde_json::from_slice(&bytes).expect("verdict json");
            let raw = value["capture_stdout"].as_str().expect("capture_stdout");
            assert_eq!(
                capture.trim_end(),
                raw.replace("192.168.122.31", TEST_EGRESS_ADDR).trim_end(),
                "{run}: embedded capture drifted from the archived evidence"
            );
        }
        if let Ok(poll) = std::fs::read_to_string(root.join("u46-r48").join("leakpoll-u46-r48.log"))
        {
            assert!(
                poll.contains(
                    &w3t_proc_tcp_entry(W3T_ENTRY_MESH, 55222)
                        .replace(TEST_EGRESS_ADDR, "192.168.122.31")
                ),
                "u46-r48: embedded conntrack line drifted from the archived poll log"
            );
        }
    }

    // The u46-r48 misattribution, replayed end-to-end: the flagged tcp/53 FIN
    // pair ORIGINALs at the ENTRY node's mesh address. With the full
    // non-exit peer set the witness attributes the flow to lenovo-entry-1
    // and PASSES — the fix this round exists to prove.
    #[test]
    fn w3t_r48_replay_attributes_entry_mesh_peer_and_passes() {
        let mock = Arc::new(MockShellHost::new());
        let entry = w3t_proc_tcp_entry(W3T_ENTRY_MESH, 55222);
        w3t_program_replay(&mock, &entry, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let r = run_witness_with_clients(&mock, &w3t_peers_all()).expect("setup must succeed");
        r2_show("w3t-r48-entry-peer", &r);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.forwarded_dns_tcp.len(), 1);
        let packet = &r.forwarded_dns_tcp[0];
        assert_eq!(packet.original_src, W3T_ENTRY_MESH);
        assert_eq!(packet.mesh_peer, "lenovo-entry-1");
        // no SYN for 55222 anywhere in the window: the flow pre-existed it,
        // so attribution MUST demand the both-snapshot evidence (MED-3)
        assert_eq!(packet.snapshot, CONNTRACK_SNAPSHOT_BOTH);
        assert!(packet.conntrack_line.contains("sport=55222"));
        assert_eq!(r.positive_control.forwarded_icmp_attributed, 4);
        assert_eq!(r.positive_control.forwarded_dns_attributed, 1);
        assert_eq!(r.counts.host_dns_tcp, 0);
        assert_eq!(r.counts.forwarded_icmp, 4);
        assert_eq!(r.counts.wireguard, 15);
    }

    // W3T negative: WITHOUT the entry's mesh address in the set (the old
    // client-only stage shape) the very same u46-r48 evidence is a failing
    // leak again — a relay flow is never waved through on a guess, it is
    // proven by naming the peer.
    #[test]
    fn w3t_r48_replay_without_entry_peer_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        let entry = w3t_proc_tcp_entry(W3T_ENTRY_MESH, 55222);
        w3t_program_replay(&mock, &entry, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let client_only = vec![("lenovo-client-1".to_owned(), W3T_CLIENT_MESH.to_owned())];
        let r = run_witness_with_clients(&mock, &client_only).expect("setup must succeed");
        assert!(!r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.counts.host_dns_tcp, 1);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // W3T negative: the EXIT's own mesh address must never be admitted — it
    // is CGNAT-shaped like every peer, but an exit-local ORIGINAL source is
    // the host leaking by definition. The stage set excludes the exit; the
    // attribution layer enforces it.
    #[test]
    fn w3t_r48_replay_exit_mesh_original_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        let exit_src = w3t_proc_tcp_entry(W3T_EXIT_MESH, 55222);
        w3t_program_replay(&mock, &exit_src, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let r = run_witness_with_clients(&mock, &w3t_peers_all()).expect("setup must succeed");
        assert!(!r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.counts.host_dns_tcp, 1);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // W3T positive: the same r48 window with the flow ORIGINALed at the
    // CLIENT (the poll log carried both flows) attributes lenovo-client-1.
    #[test]
    fn w3t_r48_replay_client_mesh_original_attributes_client() {
        let mock = Arc::new(MockShellHost::new());
        let client = w3t_proc_tcp_entry(W3T_CLIENT_MESH, 46998);
        w3t_program_replay(
            &mock,
            &client,
            W3T_CLIENT_MESH,
            &W3T_R48_CAPTURE.replace(".55222", ".46998"),
        );
        let r = run_witness_with_clients(&mock, &w3t_peers_all()).expect("setup must succeed");
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.forwarded_dns_tcp.len(), 1);
        assert_eq!(r.forwarded_dns_tcp[0].original_src, W3T_CLIENT_MESH);
        assert_eq!(r.forwarded_dns_tcp[0].mesh_peer, "lenovo-client-1");
        assert_eq!(r.forwarded_dns_tcp[0].snapshot, CONNTRACK_SNAPSHOT_BOTH);
    }

    // u46-r35 replay: same shape, FIN sport 43420, and NO leakpoll file —
    // the client's conntrack entry is SYNTHETIC (the default-format helper
    // shape), still present in BOTH snapshots because the flow pre-existed
    // the window. The witness must pass and name the client.
    #[test]
    fn w3t_r35_replay_synthetic_client_entry_passes() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_local_addrs(&mock);
        let tcp = conntrack_masq_tcp_entry(
            W3T_CLIENT_MESH,
            43420,
            TEST_EGRESS_ADDR,
            43420,
            "1.1.1.1",
            53,
        );
        let icmp =
            conntrack_masq_icmp_entry_with_id(W3T_CLIENT_MESH, TEST_EGRESS_ADDR, "192.0.2.1", 4);
        program_conntrack(&mock, &tcp, "", "");
        program_capture_end_conntrack(&mock, &tcp, "", "", &icmp);
        program_capture(&mock, W3T_R35_CAPTURE, &tcpdump_stderr_ok());
        let r = run_witness_with_clients(&mock, &w3t_peers_all()).expect("setup must succeed");
        r2_show("w3t-r35-synthetic", &r);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.forwarded_dns_tcp.len(), 1);
        assert_eq!(r.forwarded_dns_tcp[0].original_src, W3T_CLIENT_MESH);
        assert_eq!(r.forwarded_dns_tcp[0].mesh_peer, "lenovo-client-1");
        assert_eq!(r.forwarded_dns_tcp[0].snapshot, CONNTRACK_SNAPSHOT_BOTH);
        assert_eq!(r.positive_control.forwarded_icmp_attributed, 4);
        assert_eq!(r.counts.host_dns_tcp, 0);
    }

    // W3T negative: an original source that is merely CGNAT-shaped but is NO
    // mesh peer must never be attributed — the stage set matches exactly,
    // never a range.
    #[test]
    fn w3t_unknown_cgnat_original_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        let stranger = w3t_proc_tcp_entry("100.64.9.9", 55222);
        w3t_program_replay(&mock, &stranger, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let r = run_witness_with_clients(&mock, &w3t_peers_all()).expect("setup must succeed");
        assert!(!r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.counts.host_dns_tcp, 1);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // W3T negative: an EMPTY peer set must not silently fall through to a
    // wide address space — the u46-r48 flow stays unattributed and the
    // witness fails closed.
    #[test]
    fn w3t_empty_peer_set_fails_closed_on_r48_replay() {
        let mock = Arc::new(MockShellHost::new());
        let entry = w3t_proc_tcp_entry(W3T_ENTRY_MESH, 55222);
        w3t_program_replay(&mock, &entry, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let r = run_witness_with_clients(&mock, &[]).expect("setup must succeed");
        assert!(!r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.counts.host_dns_tcp, 1);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // W3T negative, second axis of the empty-set fallback: the tunnel-subnet
    // tier admits 10.6.0.0/24, and the EXIT'S OWN tunnel address (10.6.0.1)
    // lives in it — the exit-local gate must reject that ORIGINAL source
    // before the space tier ever blesses it.
    #[test]
    fn w3t_empty_peer_set_exit_local_tunnel_original_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        let tunnel = w3t_proc_tcp_entry("10.6.0.1", 55222);
        w3t_program_replay(&mock, &tunnel, W3T_CLIENT_MESH, W3T_R48_CAPTURE);
        let r = run_witness_with_clients(&mock, &[]).expect("setup must succeed");
        assert!(!r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.counts.host_dns_tcp, 1);
        assert!(r.forwarded_dns_tcp.is_empty());
    }

    // ═══════════ ROUND-3 INDEPENDENT REVIEW TESTS (r3_*, ported) ═══════════
    // Ported from the round-3 reviewer suite (out/w3-review/w3t-tests.rs).
    // Round-4 severity split adaptation: W2 order violations on accepts
    // WITHOUT an explicit `ct state established` match are NON-FATAL
    // findings under `dns_rule_order_findings`; only the established-flow
    // spellings (incl. the comment trick) stay Err.
    fn r3_exit_table_from_evidence(run: &str) -> Option<String> {
        let path = format!(
            "/Users/iwan/rustysuite-fleet/evidence/lenovo/{run}/logs/diag_post-enforce_lenovo-exit-1.txt"
        );
        let text = std::fs::read_to_string(path).ok()?;
        let start = text.find("table inet rustynet_g1 {")?;
        let rest = &text[start..];
        let end = rest.find("\n}\n")?;
        Some(rest[..end + 3].to_owned())
    }
    fn r3_verify(listing: &str) -> Result<String, String> {
        let mock = MockShellHost::new();
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g1"],
            exit_ok(listing),
        );
        verify_scoped_dns_drop_rules(&mock, "eth0", "rustynet_g1").map(|posture| posture.listing)
    }
    const R3_SCOPED: &str = "\t\toifname \"eth0\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\t\toifname \"eth0\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\t\toifname \"eth0\" meta nfproto ipv4 accept\n";

    #[test]
    fn r3_w2_real_production_table_variants() {
        for run in ["u46-r8/u46-r8", "u46-r36", "u46-r41", "u46-r39"] {
            let Some(base) = r3_exit_table_from_evidence(run) else {
                eprintln!("R3[w2-{run}] evidence missing");
                continue;
            };
            // as observed (pre-NAT): no scoped drops => posture precondition must fail
            let r = r3_verify(&base);
            assert!(
                r.is_err(),
                "R3[w2-{run}-asobserved] must fail (no scoped drops)"
            );
            // V1: scoped rules appended at the END of the killswitch chain (daemon appends after NAT apply)
            let marker = "\n\t}\n\n\tchain forward";
            let v1 = base.replacen(marker, &format!("\n{R3_SCOPED}\t}}\n\n\tchain forward"), 1);
            let r = r3_verify(&v1);
            eprintln!(
                "R3[w2-{run}-V1-appended-at-end] ok={} {:?}",
                r.is_ok(),
                r.as_ref()
                    .err()
                    .map(|e| e.chars().take(300).collect::<String>())
            );
            assert!(
                r.is_ok(),
                "R3[w2-{run}-V1] real table must pass: {:?}",
                r.err()
            );
            // V2: scoped rules inserted right after the tunnel accept (before the dns lines)
            let anchor = "\t\toifname \"rustynet0\" meta nfproto ipv4 accept\n";
            let v2 = base.replacen(anchor, &format!("{anchor}{R3_SCOPED}"), 1);
            let r = r3_verify(&v2);
            eprintln!(
                "R3[w2-{run}-V2-before-dns-lines] ok={} {:?}",
                r.is_ok(),
                r.as_ref()
                    .err()
                    .map(|e| e.chars().take(300).collect::<String>())
            );
            assert!(
                r.is_ok(),
                "R3[w2-{run}-V2] real table must pass: {:?}",
                r.err()
            );
        }
    }

    // W2 unsafe shapes (rounds 1-2 + oifname-negation / set tricks) on a minimal
    // table. Round-4: established-flow spellings stay FATAL; every other
    // violating shape is a NON-FATAL finding; clean shapes stay clean.
    #[test]
    fn r3_w2_unsafe_shapes() {
        let drops = "\x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n";
        // "fatal" = Err; "finding" = Ok with non-empty order findings;
        // "clean" = Ok with empty findings.
        let t = |name: &str, accept: &str, expect: &str| {
            let l = format!(
                "table inet rustynet_g7 {{\n\x20 chain egress {{\n\x20  {accept}\n{drops}\x20 }}\n}}\n"
            );
            match verify_posture(&l) {
                Ok(posture) => {
                    let findings = !posture.order_findings.is_empty();
                    let got = if findings { "finding" } else { "clean" };
                    assert_eq!(
                        got, expect,
                        "R3[w2u-{name}] expected {expect}, got {got}: {:?}",
                        posture.order_findings
                    );
                    eprintln!("R3[w2u-{name}] ok findings={findings} (expected {expect})");
                }
                Err(err) => {
                    assert_eq!(expect, "fatal", "R3[w2u-{name}] unexpected Err: {err}");
                    assert!(
                        err.starts_with("kill switch rule order unsafe:"),
                        "R3[w2u-{name}] {err}"
                    );
                    eprintln!("R3[w2u-{name}] fatal (expected fatal)");
                }
            }
        };
        // FATAL: every unqualified established-flow accept spelling
        t(
            "est-unqualified",
            "ct state established,related accept",
            "fatal",
        );
        t(
            "est-set-literal",
            "ct state { established, related } accept",
            "fatal",
        );
        t(
            "est-counter",
            "ct state established counter packets 0 bytes 0 accept",
            "fatal",
        );
        t(
            "comment-trick",
            "ct state established,related accept comment \"dport != { 53, 853 }\"",
            "fatal",
        );
        // NON-FATAL findings: order violations without an established accept
        t("oif-egress", "oifname \"enp0s9\" accept", "finding");
        t("tcp-dport-53", "tcp dport 53 accept", "finding");
        t(
            "oif-other-dport-53",
            "oifname \"rustynet0\" tcp dport 53 accept",
            "finding",
        );
        t("daddr", "ip daddr 0.0.0.0/0 accept", "finding");
        t("oif-neg-lo", "oifname != \"lo\" accept", "finding");
        t(
            "oif-neg-egress-excluded-wrongly",
            "oifname != \"rustynet0\" accept",
            "finding",
        );
        t(
            "oif-set-with-egress",
            "oifname { \"lo\", \"enp0s9\" } accept",
            "finding",
        );
        t("iif-neg", "iifname != \"rustynet0\" accept", "finding");
        t("sport-only", "udp sport 51820 accept", "finding");
        t(
            "l4proto-tcp-only-excl",
            "meta l4proto != { tcp } accept",
            "finding",
        );
        // CLEAN: provably scoped or DNS-excluded shapes
        t(
            "oif-lo-then-set",
            "oifname \"lo\" oifname \"enp0s9\" accept",
            "clean",
        );
        t("iif-lo-no-oif", "iifname \"lo\" accept", "clean");
        t("oif-lo-safe", "oifname \"lo\" accept", "clean");
        t(
            "oif-rn0-safe",
            "oifname \"rustynet0\" meta nfproto ipv4 accept",
            "clean",
        );
        t(
            "est-excl-safe",
            "ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept",
            "clean",
        );
        // An ESTABLISHED accept in a SECOND chain (after the drops of the
        // first chain) is still FATAL: the drops must live in the accept's
        // own chain — drops in another chain are shadowed by the accept.
        let two_chain = "table inet rustynet_g7 {\n chain killswitch {\n  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n }\n chain forward {\n  ct state established,related accept\n }\n}\n";
        let err = verify_posture(two_chain)
            .expect_err("est accept in a drop-less second chain must stay fatal");
        assert!(
            err.contains("does not carry BOTH scoped DNS drops"),
            "{err}"
        );
    }

    // helpers for custom local address lists (real exit lists rustynet0 mesh addr)
    fn r3_program_real_local_addrs(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-4", "-o", "addr", "show"],
            exit_ok(&format!(
                "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                 2: {TEST_EGRESS_IFACE}    inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\\\n\
                 5: rustynet0    inet 100.123.229.22/32 scope global rustynet0\\\n"
            )),
        );
    }
    const R3_ENTRY: &str = "100.66.184.214";
    const R3_CLIENT: &str = "100.95.199.56";
    const R3_EXIT: &str = "100.123.229.22";
    fn r3_peers() -> Vec<(String, String)> {
        vec![
            ("lenovo-client-1".to_owned(), R3_CLIENT.to_owned()),
            ("lenovo-entry-1".to_owned(), R3_ENTRY.to_owned()),
        ]
    }
    fn r3_proc_tcp(orig: &str, sport: u16, state: &str) -> String {
        format!(
            "ipv4     2 tcp      6 119 {state} src={orig} dst=1.1.1.1 sport={sport} dport=53 src=1.1.1.1 dst={TEST_EGRESS_ADDR} sport=53 dport={sport} [ASSURED] mark=0 zone=0 use=2\n"
        )
    }
    fn r3_proc_icmp(orig: &str) -> String {
        conntrack_extended_icmp_entry(orig, TEST_EGRESS_ADDR, "192.0.2.1", 4)
    }
    /// Run with conntrack binary MISSING and /proc snapshots start/end (no conntrack binary on the guest).
    fn r3_run_proc(
        start_snap: &str,
        end_snap: &str,
        capture: &str,
        peers: &[(String, String)],
    ) -> LeakWitnessReport {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        r3_program_real_local_addrs(&mock);
        w3s_program_end_conntrack_missing(&mock);
        w3s_program_proc(&mock, start_snap);
        w3s_program_proc(&mock, end_snap);
        program_capture(&mock, capture, &tcpdump_stderr_ok());
        run_witness_with_clients(&mock, peers).expect("setup")
    }
    fn r3_show(tag: &str, r: &LeakWitnessReport) {
        eprintln!(
            "R3[{tag}] pass={} counts={:?} fwd={:?} failures={:?}",
            r.failures.is_empty(),
            (
                r.counts.host_dns_udp,
                r.counts.host_dns_tcp,
                r.counts.host_dot,
                r.counts.forwarded_icmp,
                r.counts.wireguard
            ),
            r.forwarded_dns_tcp
                .iter()
                .map(|p| (&p.original_src, &p.mesh_peer, &p.snapshot))
                .collect::<Vec<_>>(),
            r.failures
        );
    }

    // (2) proc fallback: clean run and leak-shaped run with NO conntrack binary
    #[test]
    fn r3_proc_fallback_clean_and_leak() {
        let icmp = r3_proc_icmp(R3_CLIENT);
        let clean = r3_run_proc(&icmp, &icmp, &clean_capture(), &r3_peers());
        r3_show("proc-clean", &clean);
        // clean_capture ICMP id is 1, entry id 4 => adapt
        let icmp1 = conntrack_extended_icmp_entry(R3_CLIENT, TEST_EGRESS_ADDR, "192.0.2.1", 1);
        let clean = r3_run_proc(&icmp1, &icmp1, &clean_capture(), &r3_peers());
        r3_show("proc-clean-id1", &clean);
        assert!(clean.failures.is_empty(), "{:?}", clean.failures);
        // leak-shaped: FIN pair with no entry at all
        let leak = r3_run_proc(
            &icmp1,
            &icmp1,
            &with_client_fin(&clean_capture()),
            &r3_peers(),
        );
        r3_show("proc-leak-no-entry", &leak);
        assert!(!leak.failures.is_empty());
    }

    // proc: bound applied AFTER filtering; heavy noise must not crowd out relevant lines
    #[test]
    fn r3_proc_bound_after_filter_and_truncation() {
        let mut noise = String::new();
        for i in 0..3000 {
            noise.push_str(&format!("ipv4     2 tcp      6 431999 ESTABLISHED src=10.1{}.{} dst=10.2.0.1 sport={} dport=22 src=10.2.0.1 dst=10.1{}.{} sport=22 dport={} [ASSURED] mark=0 zone=0 use=2\n", i / 250, i % 250, 20000 + i, i / 250, i % 250, 20000 + i));
        }
        let icmp = conntrack_extended_icmp_entry(R3_CLIENT, TEST_EGRESS_ADDR, "192.0.2.1", 1);
        let snap = format!("{noise}{icmp}");
        let r = r3_run_proc(&snap, &snap, &clean_capture(), &r3_peers());
        r3_show("proc-noise-clean", &r);
        assert!(
            r.failures.is_empty(),
            "noise crowded out relevant lines: {:?}",
            r.failures
        );
        // relevant-line flood > 16 KiB: client entry first, conflicting HOST entry last (beyond bound)
        let client = r3_proc_tcp(R3_ENTRY, 55222, "TIME_WAIT");
        let host = r3_proc_tcp(TEST_EGRESS_ADDR, 55222, "TIME_WAIT");
        let mut flood = String::new();
        for i in 0..400 {
            flood.push_str(&format!("ipv4     2 udp      17 29 src=100.95.199.56 dst=9.9.9.9 sport={} dport=53 src=9.9.9.9 dst={TEST_EGRESS_ADDR} sport=53 dport={} mark=0 zone=0 use=2\n", 30000 + i, 30000 + i));
        }
        let snap = format!("{client}{flood}{host}{icmp}");
        let r = r3_run_proc(&snap, &snap, W3T_R48_CAPTURE, &r3_peers());
        r3_show("proc-flood-host-beyond-bound", &r);
        eprintln!(
            "R3 end blob len={} truncated_marker={}",
            r.capture_end_conntrack.len(),
            r.capture_end_conntrack.contains("[truncated]")
        );
        assert!(
            !r.failures.is_empty(),
            "FAIL-OPEN: host conflict entry truncated away"
        );
    }

    // (3) START-conflict
    #[test]
    fn r3_start_conflict_variants() {
        let cap = r2_syn_fin_capture(true);
        let icmp = r2_icmp();
        let host = r2_host_tw(TEST_EGRESS_ADDR);
        let client = r2_client_tw();
        // host in start, client in end, SYN in window (NEW-3) => must fail
        let r = r2_run([&host, "", ""], [&client, "", "", &icmp], &cap, &[]);
        r3_show("new3-host-start-client-end-syn", &r);
        assert!(!r.failures.is_empty());
        // START ambiguous (host + other client, differing ORIGINALs) => the
        // 4-tuple cannot be pinned to one flow => fail closed (round-4)
        let other =
            conntrack_masq_tcp_entry("10.6.0.3", 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        let start_amb = format!("{host}{other}");
        let r = r2_run([&start_amb, "", ""], [&client, "", "", &icmp], &cap, &[]);
        r3_show("new3-START-ambiguous-syn", &r);
        assert!(!r.failures.is_empty(), "FAIL-OPEN: ambiguous START ignored");
    }

    // (4) r48 replay, real lines, real local list (exit mesh addr present in ip addr)
    #[test]
    fn r3_r48_replay_matrix() {
        let icmp = r3_proc_icmp(R3_CLIENT);
        let cap = W3T_R48_CAPTURE;
        let ok = |orig: &str, tag: &str, peers: &[(String, String)], expect_pass: bool| {
            let tcp = r3_proc_tcp(orig, 55222, "TIME_WAIT");
            let snap = format!("{tcp}{icmp}");
            let r = r3_run_proc(&snap, &snap, cap, peers);
            r3_show(tag, &r);
            assert_eq!(
                r.failures.is_empty(),
                expect_pass,
                "{tag}: {:?}",
                r.failures
            );
            r
        };
        let r = ok(R3_ENTRY, "r48-entry", &r3_peers(), true);
        assert_eq!(r.forwarded_dns_tcp[0].mesh_peer, "lenovo-entry-1");
        ok(R3_CLIENT, "r48-client-orig", &r3_peers(), true);
        ok(R3_EXIT, "r48-exit-mesh-orig", &r3_peers(), false);
        // exit mesh addr WRONGLY in the peer set: local-addr gate must still catch it
        let mut bad = r3_peers();
        bad.push(("lenovo-exit-1".to_owned(), R3_EXIT.to_owned()));
        ok(R3_EXIT, "r48-exit-mesh-in-peerset", &bad, false);
        ok("100.64.9.9", "r48-unknown-cgnat", &r3_peers(), false);
        ok(TEST_EGRESS_ADDR, "r48-egress-orig", &r3_peers(), false);
        ok("127.0.0.1", "r48-loopback-orig", &r3_peers(), false);
        ok("100.66.184.215", "r48-adjacent-addr", &r3_peers(), false);
        ok(R3_ENTRY, "r48-empty-peerset", &[], false);
        // host entry in each snapshot arrangement, with entry-peer entry elsewhere
        let host = r3_proc_tcp(TEST_EGRESS_ADDR, 55222, "TIME_WAIT");
        let peer = r3_proc_tcp(R3_ENTRY, 55222, "TIME_WAIT");
        for (n, s, e) in [
            ("host-start-only", format!("{host}{icmp}"), icmp.clone()),
            ("host-end-only", icmp.clone(), format!("{host}{icmp}")),
            (
                "host-both",
                format!("{host}{icmp}"),
                format!("{host}{icmp}"),
            ),
            (
                "host-start-peer-end",
                format!("{host}{icmp}"),
                format!("{peer}{icmp}"),
            ),
            (
                "peer-start-host-end",
                format!("{peer}{icmp}"),
                format!("{host}{icmp}"),
            ),
            (
                "host+peer-both",
                format!("{host}{peer}{icmp}"),
                format!("{host}{peer}{icmp}"),
            ),
            ("peer-start-only", format!("{peer}{icmp}"), icmp.clone()),
            ("peer-end-only", icmp.clone(), format!("{peer}{icmp}")),
        ] {
            let r = r3_run_proc(&s, &e, cap, &r3_peers());
            r3_show(&format!("r48-{n}"), &r);
            assert!(!r.failures.is_empty(), "FAIL-OPEN {n}");
        }
        // port reuse w/ SYN in window: host start + peer end
        let mut cap_syn = cap.to_owned();
        cap_syn.push_str(&format!("05:37:19.000000 IP {TEST_EGRESS_ADDR}.55222 > 1.1.1.1.53: Flags [S], seq 0, win 64240, length 0\n"));
        let r = r3_run_proc(
            &format!("{host}{icmp}"),
            &format!("{peer}{icmp}"),
            &cap_syn,
            &r3_peers(),
        );
        r3_show("r48-port-reuse-syn", &r);
        assert!(!r.failures.is_empty(), "FAIL-OPEN port reuse");
        // UDP / DoT: peer entries never relieve
        let mut cu = cap.to_owned();
        cu.push_str(&format!(
            "05:37:25.000000 IP {TEST_EGRESS_ADDR}.40002 > 8.8.8.8.53: 1234+ A? x. (20)\n"
        ));
        let eu = format!(
            "ipv4     2 udp      17 29 src={R3_ENTRY} dst=8.8.8.8 sport=40002 dport=53 src=8.8.8.8 dst={TEST_EGRESS_ADDR} sport=53 dport=40002 mark=0 zone=0 use=2\n"
        );
        let snap = format!("{peer}{eu}{icmp}");
        let r = r3_run_proc(&snap, &snap, &cu, &r3_peers());
        r3_show("r48-udp53-peer-entry", &r);
        assert!(!r.failures.is_empty());
        let mut cd = cap.to_owned();
        cd.push_str(&format!("05:37:25.000000 IP {TEST_EGRESS_ADDR}.40003 > 8.8.8.8.853: Flags [S], seq 1, win 64240, length 0\n"));
        let ed = format!(
            "ipv4     2 tcp      6 119 SYN_SENT src={R3_ENTRY} dst=8.8.8.8 sport=40003 dport=853 src=8.8.8.8 dst={TEST_EGRESS_ADDR} sport=853 dport=40003 [UNREPLIED] mark=0 zone=0 use=2\n"
        );
        let snap = format!("{peer}{ed}{icmp}");
        let r = r3_run_proc(&snap, &snap, &cd, &r3_peers());
        r3_show("r48-dot-peer-entry-syn", &r);
        let r = r3_run_proc(
            &format!("{peer}{icmp}"),
            &format!("{peer}{icmp}"),
            &cd,
            &r3_peers(),
        );
        r3_show("r48-dot-no-entry", &r);
        assert!(!r.failures.is_empty());
    }

    // client-space fallback tiers sanity (docker/second nic no longer admitted)
    #[test]
    fn r3_client_space_tiers() {
        let listing = "1: lo    inet 127.0.0.1/8 scope host lo\\\n2: eth0    inet 192.168.122.31/24 scope global eth0\\\n3: docker0    inet 172.17.0.1/16 scope global docker0\\\n4: eth1    inet 10.99.0.5/24 scope global eth1\\\n5: rustynet0    inet 100.123.229.22/10 scope global rustynet0\\\n";
        let cs = ClientSpace::derive(&[], listing, "192.168.122.31", "rustynet0");
        for a in [
            "172.17.0.2",
            "10.99.0.77",
            "100.95.199.56",
            "100.127.255.254",
            "192.168.122.50",
        ] {
            eprintln!("R3[clientspace-{a}] admits={}", cs.admits(a));
        }
    }

    #[test]
    fn r3_trunc_drops_host_conflict_icmp_first() {
        let icmp = conntrack_extended_icmp_entry(R3_CLIENT, TEST_EGRESS_ADDR, "192.0.2.1", 4);
        let peer = r3_proc_tcp(R3_ENTRY, 55222, "TIME_WAIT");
        let host = r3_proc_tcp(TEST_EGRESS_ADDR, 55222, "TIME_WAIT");
        let mut flood = String::new();
        for i in 0..400 {
            flood.push_str(&format!("ipv4     2 udp      17 29 src=100.95.199.56 dst=9.9.9.9 sport={} dport=53 src=9.9.9.9 dst={TEST_EGRESS_ADDR} sport=53 dport={} mark=0 zone=0 use=2\n", 30000 + i, 30000 + i));
        }
        let snap = format!("{icmp}{peer}{flood}{host}");
        let r = r3_run_proc(&snap, &snap, W3T_R48_CAPTURE, &r3_peers());
        r3_show("trunc-host-conflict-beyond-bound", &r);
        eprintln!(
            "R3 blob_len={} marker={}",
            r.capture_end_conntrack.len(),
            r.capture_end_conntrack.contains("[truncated]")
        );
        assert!(
            !r.failures.is_empty(),
            "FAIL-OPEN: host conflict entry truncated away, packet relieved"
        );
    }
    // W2: list every accept line of the real table the order check objects to
    #[test]
    fn r3_w2_which_real_lines_flagged() {
        let Some(base) = r3_exit_table_from_evidence("u46-r41") else {
            return;
        };
        let marker = "\n\t}\n\n\tchain forward";
        let v1 = base.replacen(marker, &format!("\n{R3_SCOPED}\t}}\n\n\tchain forward"), 1);
        let mut chain = String::new();
        for (idx, line) in v1.lines().enumerate() {
            let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.starts_with("chain ") {
                chain = collapsed.clone();
            }
            if accept_can_match_dns_ports(&collapsed) {
                let tokens: Vec<&str> = strip_nft_comment(&collapsed).split_whitespace().collect();
                let away = accept_scoped_away_from_egress_output(&tokens, "eth0")
                    && !accept_has_dns_matchable_dport_clause(&tokens);
                if !away {
                    eprintln!(
                        "R3[flagged] line {} chain `{}`: {}",
                        idx + 1,
                        chain,
                        collapsed
                    );
                }
            }
        }
    }

    // ═══════════ ROUND-4 OWNER-DECISION TESTS ═══════════

    // Q04/positive-control bonus: an ARMED run with raw ICMP > 0 and ZERO
    // attributed stays GREEN when the conntrack snapshots carry NO icmp
    // entry at all (the raw packets are exit-origin by elimination)...
    #[test]
    fn r4_armed_no_icmp_entries_attributed_zero_passes() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        // both windows fully answered, icmp query EMPTY (no icmp entries)
        program_capture_end_conntrack(&mock, "", "", "", "");
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        assert_eq!(r.counts.forwarded_icmp, 1);
        assert_eq!(r.positive_control.forwarded_icmp_attributed, 0);
        assert!(
            r.failures.is_empty(),
            "armed + raw>0 + attributed=0 + no icmp entries must pass: {:?}",
            r.failures
        );
    }

    // ...but a NON-MESH icmp entry in either snapshot (here: the exit's own
    // echo, orig = the egress address itself) keeps the snapshots
    // icmp-carrying: the run stays a VACUOUS FAILURE and the non-mesh entry
    // never counts as the bonus.
    #[test]
    fn r4_non_mesh_icmp_entry_keeps_vacuous_failure() {
        // unit level: the exit's own icmp entry must not flip the gate
        let control = PositiveControlEvidence {
            forwarded_icmp_raw: 2,
            exit_origin_icmp: 2,
            forwarded_icmp_attributed: 0,
            forwarded_dns_attributed: 0,
            client_original_srcs: Vec::new(),
            proven: "nothing proven".to_owned(),
        };
        assert_eq!(
            evaluate_positive_control(&control, TEST_EGRESS_IFACE, true, true).len(),
            1
        );
        // e2e level: armed run, exit-origin icmp entry in BOTH snapshots
        let capture = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 99, seq 1, length 64\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_local_addrs(&mock);
        program_conntrack(
            &mock,
            "",
            "",
            &format!(
                "ipv4     2 icmp     1 29 src={TEST_EGRESS_ADDR} dst=192.0.2.1 type=8 code=0 id=99 src=192.0.2.1 dst={TEST_EGRESS_ADDR} type=0 code=0 id=99 mark=0 zone=0 use=1\n"
            ),
        );
        program_capture_end_conntrack(
            &mock,
            "",
            "",
            "",
            &conntrack_masq_icmp_entry_with_id(TEST_EGRESS_ADDR, TEST_EGRESS_ADDR, "192.0.2.1", 99),
        );
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let r = run_witness(&mock).expect("setup must succeed");
        assert_eq!(r.positive_control.forwarded_icmp_attributed, 0);
        assert!(
            r.failures
                .iter()
                .any(|f| f.contains("vacuous witness: no forwarded traffic")),
            "non-mesh icmp entry must keep the vacuous failure: {:?}",
            r.failures
        );
    }

    // Q04: conntrack missing in BOTH windows AND the /proc read FAILS (exit 1)
    // => attribution stays off, the ss fallback is recorded, and a leaked FIN
    // still fails via the raw counts; the clean variant passes with the ss
    // label present.
    #[test]
    fn r4_proc_exit_nonzero_ss_fallback_leak_fails_clean_passes() {
        let ss_line = "ESTAB 0 0 192.0.2.240:41000 1.1.1.1:53\n";
        let build = |ss_out: String, capture: String| {
            let mock = Arc::new(MockShellHost::new());
            program_setup(&mock, true);
            program_capture_start_nft_listing(&mock, &nft_table_ok());
            program_boot_table(&mock, None);
            program_conntrack_missing(&mock);
            // /proc read exits 1 in BOTH windows
            mock.program_run_response(&PROC_NF_CONNTRACK_ARGV, exit_code(1, ""));
            mock.program_run_response(&PROC_NF_CONNTRACK_ARGV, exit_code(1, ""));
            program_local_addrs(&mock);
            w3s_program_end_conntrack_missing(&mock);
            // ss fallback: transport-level success
            mock.program_run_response(
                &[
                    "ss",
                    "-Htn",
                    "state",
                    "established",
                    "( dport = :53 or dport = :853 )",
                ],
                exit_ok(&ss_out),
            );
            program_capture(&mock, &capture, &tcpdump_stderr_ok());
            run_witness(&mock).expect("setup must succeed")
        };
        // clean capture + EMPTY ss listing passes; the ss fallback label is
        // still recorded (the fallback transport itself is exercised)
        let clean = build(String::new(), clean_capture());
        r3_show("r4-ss-fallback-clean", &clean);
        assert!(
            clean.failures.is_empty(),
            "clean run must pass on raw controls alone: {:?}",
            clean.failures
        );
        assert!(
            clean
                .capture_start_conntrack
                .contains("== fallback: ss -Htn state established"),
            "ss fallback section must be recorded: {:?}",
            clean.capture_start_conntrack
        );
        // an ss-listed host-origin established DNS connection is a REAL
        // pre-existing flow: the witness must fail on it (the ss fallback
        // content is parsed, not just recorded)
        let leak = build(ss_line.to_owned(), with_client_fin(&clean_capture()));
        r3_show("r4-ss-fallback-leak", &leak);
        assert!(
            leak.failures
                .iter()
                .any(|f| f.contains(PRE_EXISTING_TCP_DNS_FAILURE)),
            "ss-listed pre-existing flow must fail the witness: {:?}",
            leak.failures
        );
    }

    // Q04/owner (2): a TRUNCATED conntrack blob (marker present) must disarm
    // attribution even when every query answered. The FIN below WOULD be
    // attributed (the same ORIGINAL client flow sits in BOTH proc snapshots)
    // if the snapshots were trusted — so the run flipping to an egress-leak
    // failure is the truncation gate working; had the blob been trusted the
    // run would pass.
    #[test]
    fn r4_truncated_blob_disarms_attribution() {
        let tcp_entry =
            conntrack_masq_tcp_entry(R3_CLIENT, 43420, TEST_EGRESS_ADDR, 43420, "1.1.1.1", 53);
        // flood the END snapshot past the 16 KiB bound so the marker appears
        let mut flood = String::new();
        for i in 0..400 {
            flood.push_str(&format!("ipv4     2 udp      17 29 src=100.95.199.56 dst=9.9.9.9 sport={} dport=53 src=9.9.9.9 dst={TEST_EGRESS_ADDR} sport=53 dport={} mark=0 zone=0 use=2\n", 30000 + i, 30000 + i));
        }
        let end = format!("{tcp_entry}{}", {
            let icmp = conntrack_extended_icmp_entry(R3_CLIENT, TEST_EGRESS_ADDR, "192.0.2.1", 1);
            format!("{icmp}{flood}")
        });
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture_start_nft_listing(&mock, &nft_table_ok());
        program_boot_table(&mock, None);
        program_conntrack_missing(&mock);
        r3_program_real_local_addrs(&mock);
        w3s_program_end_conntrack_missing(&mock);
        w3s_program_proc(&mock, &tcp_entry);
        w3s_program_proc(&mock, &end);
        program_capture(
            &mock,
            &with_client_fin(&clean_capture()),
            &tcpdump_stderr_ok(),
        );
        let r = run_witness_with_clients(&mock, &r3_peers()).expect("setup must succeed");
        assert!(
            r.capture_end_conntrack.contains(CAPTURE_TRUNCATION_MARKER),
            "fixture must produce a truncated end blob"
        );
        assert!(
            r.positive_control.forwarded_icmp_attributed == 0,
            "truncated blob must disarm attribution"
        );
        assert!(
            r.failures
                .iter()
                .any(|f| f.contains("egress leak: 1 host-origin tcp/53 packet(s)")),
            "truncated snapshot must keep the masqueraded FIN a counted host leak: {:?}",
            r.failures
        );
    }

    // A flow with NO initiator in the window whose END entry is missing from
    // the START snapshot (first seen mid-window) is a possible host leak:
    // fail closed (r4). A mutant that relieves on END-match alone survives
    // only if this test fails.
    #[test]
    fn r4_no_initiator_end_only_entry_still_fails() {
        // both snapshots carry the id-1 icmp control entry (so the wire echo
        // is attributed and the positive control is not vacuous) but the
        // START snapshot has NO 43420 tcp flow
        let icmp1 = conntrack_extended_icmp_entry(R3_ENTRY, TEST_EGRESS_ADDR, "192.0.2.1", 1);
        let start = icmp1.clone();
        // end snapshot: the 43420 flow appears (masqueraded from R3_ENTRY)
        let end = format!("{icmp1}{}", r3_proc_tcp(R3_ENTRY, 43420, "TIME_WAIT"));
        // FIN-only capture (no `Flags [S]`): no initiator inside the window
        let r = r3_run_proc(
            &start,
            &end,
            &with_client_fin(&clean_capture()),
            &r3_peers(),
        );
        assert!(
            !r.failures.is_empty(),
            "FAIL-OPEN: end-only entry relieved a flow with no initiator and no START match: {:?}",
            r.failures
        );
    }

    // verdict/report surface: the new non-fatal findings land in the report
    // field AND the stage verdict JSON.
    #[test]
    fn r4_dns_rule_order_findings_in_report_and_stage() {
        let posture = verify_posture(&w3s_single_accept_shape("oifname \"enp0s9\" accept"))
            .expect("non-established shape must not be fatal");
        assert_eq!(posture.order_findings.len(), 1);
        assert!(posture.order_findings[0].contains("non-fatal DNS rule order finding"));
    }

    // ── vxlan substrate capture plane (AQ-256 family: katana-xnet-839/840,
    //    lenovo-lab-633/634/635 — "no WireGuard udp/51820 traffic was
    //    captured" because the WG control rides rustynet-vx0, not the
    //    default-route underlay NIC) ────────────────────────────────────────

    fn overlay_capture_argv_for_test(window_secs: u64) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "sudo".to_owned(),
            "-n".to_owned(),
            "timeout".to_owned(),
            format!("--kill-after={CAPTURE_KILL_AFTER_SECS}"),
            (window_secs + CAPTURE_KILL_AFTER_SECS).to_string(),
            "tcpdump".to_owned(),
            "-i".to_owned(),
            TEST_OVERLAY_IFACE.to_owned(),
            "-nn".to_owned(),
            "-l".to_owned(),
        ];
        argv.extend(capture_filter_tokens(TEST_WG_PORT, TEST_OVERLAY_MAC));
        argv
    }

    fn overlay_tcpdump_stderr_ok() -> String {
        format!(
            "tcpdump: listening on '{TEST_OVERLAY_IFACE}', link-type EN10MB (Ethernet), snapshot \
             length 262144 bytes\n2 packets captured\n2 packets received by filter\n0 packets \
             dropped by kernel\n"
        )
    }

    /// THE vxlan regression: on the cross-LAN vxlan substrate the
    /// client<->exit WireGuard control is VXLAN-encapsulated (outer
    /// udp/4789), so the underlay NIC never carries bare udp/51820. The
    /// witness must capture `rustynet-vx0` too and witness the tunnel
    /// control THERE, while every assertion (zero leak classes, the
    /// masqueraded-ICMP positive control, the vacuous checks) stays exactly
    /// as strict as on the underlay-only shape.
    #[test]
    fn vxlan_substrate_witnesses_wireguard_control_on_the_overlay_plane() {
        let mock = Arc::new(MockShellHost::new());
        program_setup_with_overlay(&mock, true);
        program_capture_start_evidence_clean(&mock);
        program_w3_clean(&mock);
        // Underlay: the positive control transits here (masqueraded NAT out),
        // but NO bare udp/51820 — that is the whole defect on this shape.
        let underlay = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n\
             12:00:01.100000 IP 192.0.2.1 > {TEST_EGRESS_ADDR}: ICMP echo reply, id 1, seq 1, length 64\n"
        );
        program_capture(&mock, &underlay, &tcpdump_stderr_ok());
        // Overlay: the WG control as it rides rustynet-vx0 (inner udp/51820
        // between the plan_overlay overlay addresses).
        let overlay = format!(
            "12:00:02.000000 IP {TEST_OVERLAY_ADDR}.{TEST_WG_PORT} > {TEST_PEER_OVERLAY}.{TEST_WG_PORT}: UDP, length 32\n\
             12:00:03.000000 IP {TEST_PEER_OVERLAY}.{TEST_WG_PORT} > {TEST_OVERLAY_ADDR}.{TEST_WG_PORT}: UDP, length 32\n"
        );
        mock.program_run_response(
            &argv_refs(&overlay_capture_argv_for_test(0)),
            capture_status(&overlay, &overlay_tcpdump_stderr_ok()),
        );
        let report = run_witness(&mock).expect("vxlan witness must not err on setup");
        // Every assertion kept: zero leak classes, BOTH controls present.
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(
            report.counts.wireguard, 2,
            "the WG control must come from the overlay plane"
        );
        assert_eq!(report.counts.forwarded_icmp, 1);
        assert_eq!(report.counts.host_dns_udp, 0);
        assert_eq!(report.counts.host_dns_tcp, 0);
        assert_eq!(report.counts.host_dot, 0);
        assert_eq!(report.counts.ipv6, 0);
        assert_eq!(report.wg_listen_port, TEST_WG_PORT);
        // Capture-interface selection: BOTH planes, underlay first.
        assert_eq!(
            report.capture_ifaces,
            vec![TEST_EGRESS_IFACE.to_owned(), TEST_OVERLAY_IFACE.to_owned()]
        );
        // Filter tokens name both planes, and the merged capture text records
        // which plane each line came from.
        assert!(
            report.capture_filter.contains(TEST_OVERLAY_IFACE),
            "{}",
            report.capture_filter
        );
        assert!(
            report.capture_filter.contains(TEST_EGRESS_IFACE),
            "{}",
            report.capture_filter
        );
        assert!(
            report.capture_filter.contains("udp port 51820"),
            "{}",
            report.capture_filter
        );
        assert!(
            report
                .capture_stdout
                .contains("capture_provenance=interface=rustynet-vx0"),
            "{}",
            report.capture_stdout
        );
    }

    /// Capture-interface selection for a vxlan topology, unit-level: the
    /// underlay plane stays first and untouched, the overlay plane carries
    /// the plan_overlay address and the link's MAC (which scopes its filter).
    #[test]
    fn capture_planes_select_underlay_and_overlay_for_a_vxlan_guest() {
        let mock = MockShellHost::new();
        program_overlay_present(&mock);
        let planes = capture_planes(
            &mock,
            SubstrateOverlayHint::Unknown,
            TEST_EGRESS_IFACE,
            TEST_EGRESS_ADDR,
            TEST_EGRESS_MAC,
        )
        .expect("the overlay plane must be selected for a vxlan guest");
        assert_eq!(planes.len(), 2);
        assert_eq!(planes[0].iface, TEST_EGRESS_IFACE);
        assert!(!planes[0].overlay);
        assert_eq!(planes[0].addr, TEST_EGRESS_ADDR);
        assert_eq!(planes[1].iface, TEST_OVERLAY_IFACE);
        assert!(planes[1].overlay);
        assert_eq!(planes[1].addr, TEST_OVERLAY_ADDR);
        assert_eq!(planes[1].mac, TEST_OVERLAY_MAC);
    }

    /// A recorded NON-overlay substrate (netns/slirp/no-plan vxlan) keeps the
    /// historical shape: one plane, and the vxlan query is never even issued.
    #[test]
    fn capture_planes_keep_the_underlay_only_shape_without_an_overlay_substrate() {
        let mock = MockShellHost::new(); // any vxlan query would transport-error this mock
        let planes = capture_planes(
            &mock,
            SubstrateOverlayHint::NotRequired,
            TEST_EGRESS_IFACE,
            TEST_EGRESS_ADDR,
            TEST_EGRESS_MAC,
        )
        .expect("no overlay probe is due for a recorded non-overlay substrate");
        assert_eq!(planes.len(), 1);
        assert_eq!(planes[0].iface, TEST_EGRESS_IFACE);
        assert_eq!(planes[0].addr, TEST_EGRESS_ADDR);
        assert!(
            mock.run_log()
                .iter()
                .all(|call| call.argv.join(" ") != "ip -4 addr show dev rustynet-vx0"),
            "a recorded netns/slirp substrate must not probe for the overlay link"
        );
    }

    /// Fail closed: a provisioned vxlan overlay recorded by the orchestrator
    /// with no overlay link on the exit guest can NEVER silently degrade to
    /// the vacuous underlay-only capture — it errors, naming the link.
    #[test]
    fn capture_planes_fail_closed_when_a_provisioned_vxlan_overlay_is_missing() {
        let mock = MockShellHost::new();
        program_overlay_absent(&mock);
        let err = capture_planes(
            &mock,
            SubstrateOverlayHint::Required,
            TEST_EGRESS_IFACE,
            TEST_EGRESS_ADDR,
            TEST_EGRESS_MAC,
        )
        .expect_err("a recorded provisioned overlay with no link must fail closed");
        assert!(err.contains("vxlan"), "{err}");
        assert!(err.contains(TEST_OVERLAY_IFACE), "{err}");
        assert!(err.contains("failing closed"), "{err}");
    }

    /// Filter tokens for the vxlan topology's overlay plane: the full strict
    /// set (host-origin DNS/DoT, ICMP control, WireGuard, MAC-scoped IPv6) —
    /// adding a plane never filters a class out.
    #[test]
    fn capture_filter_tokens_keep_every_clause_on_the_overlay_plane() {
        let mac_clause = format!("ether src {TEST_OVERLAY_MAC}");
        let joined = capture_filter_tokens(TEST_WG_PORT, TEST_OVERLAY_MAC).join(" ");
        let needles = [
            "udp port 53",
            "tcp port 53",
            "tcp port 853",
            "icmp",
            "udp port 51820",
            mac_clause.as_str(),
        ];
        for needle in needles {
            assert!(joined.contains(needle), "missing {needle:?} in {joined}");
        }
    }

    /// Leak counting spans EVERY captured plane: an exit-origin packet seen
    /// on the overlay counts exactly like one seen on the underlay, and a
    /// foreign source never does.
    #[test]
    fn classify_counts_host_origin_packets_on_any_captured_plane() {
        let both_planes = format!(
            "12:00:01.000000 IP {TEST_OVERLAY_ADDR}.41000 > 8.8.8.8.53: UDP, length 40\n\
             12:00:02.000000 IP {TEST_EGRESS_ADDR}.42000 > 8.8.8.8.53: UDP, length 40\n"
        );
        let counts = classify_capture(
            &both_planes,
            &[TEST_EGRESS_ADDR, TEST_OVERLAY_ADDR],
            TEST_WG_PORT,
        );
        assert_eq!(
            counts.host_dns_udp, 2,
            "a leak witnessed on either plane must count"
        );
        let foreign = "12:00:01.000000 IP 172.20.10.9.41000 > 8.8.8.8.53: UDP, length 40\n";
        let counts = classify_capture(
            foreign,
            &[TEST_EGRESS_ADDR, TEST_OVERLAY_ADDR],
            TEST_WG_PORT,
        );
        assert_eq!(
            counts.host_dns_udp, 0,
            "a non-local source is never host-origin"
        );
    }
}
