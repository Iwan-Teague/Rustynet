#![forbid(unsafe_code)]
//! CS4 - OPT-IN expected-listener-set control-surface check.
//!
//! **OWNER MUST APPROVE the check redefinition before this is made active.**
//! Nothing in the default lab flow calls this module: the shipped
//! `rustynet_udp_loopback_only` / `no_rustynet_tcp_listeners` definition in
//! `ops_live_lab_orchestrator` is untouched. It is reachable only through
//! `live_linux_control_surface_exposure_test --expected-listener-set`
//! (CLI flag only — there is deliberately NO environment-variable switch).
//!
//! Why it exists. The shipped check says "no rustynetd TCP listener, and the
//! only rustynetd UDP listener is the DNS resolver". That definition predates
//! the userspace WireGuard backend (whose data-plane socket
//! `0.0.0.0:<wg_port>` is owned by `rustynetd` and MUST be reachable from the
//! underlay) and the gossip transport (which binds the node's overlay
//! address). It therefore fails on every healthy userspace-backend node, and
//! worse it cannot tell a healthy node from one with a real leak: it has no
//! positive expectations, so it neither notices a missing resolver nor a
//! gossip socket that regressed to a wildcard bind.
//!
//! The expected-set check replaces "everything but DNS is forbidden" with an
//! EXACT per-node listener set, positive and negative:
//!
//! 1. `udp <dns_bind_addr>` present exactly once.
//! 2. WireGuard port: on the userspace backend exactly one `udp <addr>` whose
//!    address equals the daemon's own `transport_socket_identity_local_addr`
//!    (cross-checked against `rustynet status`, never hard-coded); on the
//!    kernel backend (`blocked_backend_opaque_socket`) NO rustynetd socket on
//!    that port. An unknown backend fails.
//! 3. Gossip: exactly one `udp <rustynet0 IPv4>:51821` iff `gossip_state` is
//!    `active`, and the address equals the IPv4 of `rustynet0` captured in the
//!    same ssh session; any wildcard/other bind, or a gossip socket while
//!    gossip is not active, fails.
//! 4. TCP: none, except exactly `tcp 127.0.0.1:51822` on nodes whose signed
//!    record holds `anchor.bundle_pull` (required there, forbidden elsewhere).
//! 5. Any other rustynetd listener (including a second wildcard) fails; any
//!    parse failure fails (fail closed).
//! 6. Optional (`expect_gossip_scope_table`): the CS3 `rustynet_svc_gossip`
//!    input chain is an accept-policy input hook at the reviewed `-10`
//!    priority holding exactly the reviewed loopback-accept plus the
//!    tunnel-scope drop PINNED to `rustynet0` (the tunnel interface of this
//!    deployment — a drop for any other interface is drift).
//! 7. Active probe from a peer to the node's UNDERLAY IP: TCP/51822 must not
//!    connect and UDP/51821 must not answer, and the probe's TCP/22 positive
//!    control (sshd — the lab cannot run without it) MUST answer, else the
//!    whole probe is vacuous and the verdict fails. Honest limits: a UDP
//!    datagram to a silent socket and to a dropped port look the same from
//!    outside, so the UDP probe catches an answering service only; and the
//!    probe targets the UNDERLAY address, while the weak-host attack it
//!    guards against reaches the node via the OVERLAY address over the
//!    underlay link. With CS1 in place nothing listens on the underlay
//!    address at all, so the kernel-level proof of the interface pin is
//!    check 6 plus the netns witness shipped with CS3.
//!
//! It is strictly stricter than the shipped check except that it admits the
//! three product-owned listeners above (the userspace WireGuard socket, the
//! overlay-bound gossip socket, the loopback anchor pull socket); the property
//! tests at the bottom prove that against a mirror of the shipped logic that
//! is itself differentially tested against the real report writer. It is
//! AND-ed with the shipped report: the verdict requires the expected set to
//! pass AND the primary report's daemon/helper socket checks (aggregate and
//! per host), its `remote_underlay_dns_probe_blocked` != `fail` — see
//! `shipped_check_gate_defects`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The gossip UDP port (mirror of `rustynetd::gossip_transport::RUSTYNET_GOSSIP_PORT`).
pub const GOSSIP_PORT: u16 = 51821;
/// The anchor bundle-pull loopback listener (mirror of
/// `rustynetd::daemon::DEFAULT_ANCHOR_BUNDLE_PULL_ADDR`).
pub const ANCHOR_PULL_ADDR: &str = "127.0.0.1:51822";
/// The anchor capability whose holders (and only they) may listen on TCP.
pub const ANCHOR_BUNDLE_PULL_CAPABILITY: &str = "anchor.bundle_pull";
/// The CS3 gossip scope table.
pub const GOSSIP_SCOPE_TABLE: &str = "rustynet_svc_gossip";

/// Which WireGuard data plane the node runs, as the DAEMON reports it
/// (`transport_socket_identity_state`), never from orchestrator config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireguardBackend {
    /// `authoritative_backend_shared_transport`: rustynetd owns the UDP socket
    /// at `local_addr` (e.g. `0.0.0.0:51820`).
    Userspace { local_addr: String },
    /// `blocked_backend_opaque_socket`: kernel WireGuard; no rustynetd socket.
    Kernel,
    /// Anything else, or no answer: cannot be judged, fails closed.
    Unknown(String),
}

/// What the node told us about itself, parsed from `rustynet status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonSelfReport {
    pub node_id: Option<String>,
    pub backend: WireguardBackend,
    pub gossip_state: Option<String>,
}

/// Parse the single-line `rustynet status` output (space-separated
/// `key=value`). Duplicate keys: the first wins, like the daemon's readers.
pub fn parse_status(status_text: &str) -> DaemonSelfReport {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for token in status_text.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            fields.entry(key).or_insert(value);
        }
    }
    let backend = match fields.get("transport_socket_identity_state").copied() {
        Some("authoritative_backend_shared_transport") => {
            match fields.get("transport_socket_identity_local_addr").copied() {
                Some(addr) if !addr.is_empty() && addr != "none" => WireguardBackend::Userspace {
                    local_addr: addr.to_owned(),
                },
                other => WireguardBackend::Unknown(format!(
                    "userspace backend reported no usable local addr: {other:?}"
                )),
            }
        }
        Some("blocked_backend_opaque_socket") => WireguardBackend::Kernel,
        Some(other) => WireguardBackend::Unknown(format!(
            "unrecognised transport_socket_identity_state={other}"
        )),
        None => WireguardBackend::Unknown(
            "status carries no transport_socket_identity_state".to_owned(),
        ),
    };
    DaemonSelfReport {
        node_id: fields.get("node_id").map(|v| (*v).to_owned()),
        backend,
        gossip_state: fields.get("gossip_state").map(|v| (*v).to_owned()),
    }
}

/// First IPv4 address of `ip -4 -o addr show dev rustynet0` output
/// (`2: rustynet0    inet 100.64.0.1/32 scope global rustynet0 ...`).
pub fn parse_rustynet0_ipv4(ip_addr_output: &str) -> Option<String> {
    ip_addr_output.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        while let Some(token) = parts.next() {
            if token == "inet" {
                let cidr = parts.next()?;
                let (addr, prefix) = cidr.split_once('/')?;
                addr.parse::<std::net::Ipv4Addr>().ok()?;
                prefix.parse::<u8>().ok()?;
                return Some(addr.to_owned());
            }
        }
        None
    })
}

/// Whether `rustynet anchor list` shows `node_id` holding exactly the
/// `anchor.bundle_pull` capability entry (CSV entry match, not substring).
/// `Err` when the node has no row at all (cannot judge).
pub fn node_holds_bundle_pull(anchor_list: &str, node_id: &str) -> Result<bool, String> {
    let mut row_seen = false;
    for line in anchor_list.lines() {
        let trimmed = line.trim();
        let Some((head, csv)) = trimmed.split_once("capabilities=") else {
            continue;
        };
        if head.split_whitespace().next() != Some(node_id) {
            continue;
        }
        row_seen = true;
        if csv
            .trim()
            .split(',')
            .any(|entry| entry.trim() == ANCHOR_BUNDLE_PULL_CAPABILITY)
        {
            return Ok(true);
        }
    }
    if row_seen {
        Ok(false)
    } else {
        // A node absent from `anchor list` simply holds no anchor capability
        // (the list names anchors only); but an EMPTY or unparsable capture
        // is "cannot judge", which the caller maps to a failure.
        if anchor_list.trim().is_empty() {
            Err("anchor list capture is empty".to_owned())
        } else {
            Ok(false)
        }
    }
}

/// One parsed `ss -H -ltnup` line that names `rustynetd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustynetdListener {
    pub proto: String,
    pub local_addr: String,
    pub raw: String,
}

/// Parse the `rustynetd` listener lines of `ss -H -ltnup`. Any line that
/// mentions `rustynetd` but cannot be parsed into (netid, state, local addr)
/// is an `Err` (fail closed), unlike the shipped check which silently skips
/// some shapes.
pub fn parse_rustynetd_listeners(ss_output: &str) -> Result<Vec<RustynetdListener>, String> {
    let mut listeners = Vec::new();
    for line in ss_output.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !line.contains("rustynetd") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (Some(proto), Some(state), Some(local)) = (parts.first(), parts.get(1), parts.get(4))
        else {
            return Err(format!("unparsable rustynetd listener line: {line}"));
        };
        let proto_ok = matches!(*proto, "tcp" | "udp");
        let state_ok = matches!(*state, "LISTEN" | "UNCONN");
        if !proto_ok || !state_ok || !local.contains(':') {
            return Err(format!("unparsable rustynetd listener line: {line}"));
        }
        // `ss -n` can print the IPv4 wildcard as `*:port`; normalise.
        let local_addr = local
            .strip_prefix("*:")
            .map_or_else(|| (*local).to_owned(), |port| format!("0.0.0.0:{port}"));
        listeners.push(RustynetdListener {
            proto: (*proto).to_owned(),
            local_addr,
            raw: line.to_owned(),
        });
    }
    Ok(listeners)
}

/// Outcome of one active probe from a peer to this node's underlay IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Connected / got a reply: the port is reachable from the underlay.
    Answered,
    /// Refused / unreachable / silent.
    NoAnswer,
    /// The probe could not run (missing tool, ssh failure, garbage output).
    Inconclusive,
}

impl ProbeOutcome {
    pub fn parse(output: &str) -> Self {
        match output.trim() {
            "answered" => Self::Answered,
            "no_answer" => Self::NoAnswer,
            _ => Self::Inconclusive,
        }
    }
}

/// Underlay probe results for one node (TCP/51822 and UDP/51821 from the
/// node's UNDERLAY address).
///
/// `tcp_positive_control` is the CS4 fix for the vacuous-probe defect: a
/// TCP connect to the node's sshd (tcp/22) MUST answer — the lab depends on
/// ssh, so a silent tcp/22 means the probe harness itself is broken
/// (missing `timeout`, no `/dev/tcp` support in the peer's shell) and the
/// `no_answer` results above are worthless. The verdict fails unless the
/// control answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnderlayProbe {
    pub tcp_pull: ProbeOutcome,
    pub udp_gossip: ProbeOutcome,
    pub tcp_positive_control: ProbeOutcome,
}

/// Everything captured about one node, as text (so the evaluator is pure).
#[derive(Debug, Clone)]
pub struct HostEvidence {
    pub label: String,
    pub ss_output: String,
    pub status_text: String,
    pub rustynet0_addr_output: String,
    pub anchor_list_output: String,
    /// `nft list table inet rustynet_svc_gossip` output; `None` when not captured.
    pub gossip_scope_table_output: Option<String>,
    /// `None` when no probe host was available (reported as skipped, not pass).
    pub underlay_probe: Option<UnderlayProbe>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedSetOptions {
    /// Require the CS3 `rustynet_svc_gossip` table (set once CS3 is deployed).
    pub expect_gossip_scope_table: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostVerdict {
    pub label: String,
    pub pass: bool,
    pub reasons: Vec<String>,
    pub probe: String,
}

/// Evaluate one node. Pure; every failure carries a reason; no reasons <=> pass.
pub fn evaluate_host(
    evidence: &HostEvidence,
    dns_bind_addr: &str,
    options: ExpectedSetOptions,
) -> HostVerdict {
    let mut reasons: Vec<String> = Vec::new();
    let status = parse_status(&evidence.status_text);
    let overlay_ipv4 = parse_rustynet0_ipv4(&evidence.rustynet0_addr_output);

    // ── Which listeners must exist on THIS node ─────────────────────────
    let mut expected: Vec<(&'static str, String)> = vec![("udp", dns_bind_addr.to_owned())];
    match &status.backend {
        WireguardBackend::Userspace { local_addr } => {
            expected.push(("udp", local_addr.clone()));
        }
        WireguardBackend::Kernel => {}
        WireguardBackend::Unknown(why) => {
            reasons.push(format!("wireguard backend cannot be determined: {why}"));
        }
    }
    match status.gossip_state.as_deref() {
        Some("active") => match overlay_ipv4.as_deref() {
            Some(ip) => expected.push(("udp", format!("{ip}:{GOSSIP_PORT}"))),
            None => reasons.push(
                "gossip_state=active but rustynet0 has no IPv4 address in the same session"
                    .to_owned(),
            ),
        },
        Some(_) => {}
        None => reasons.push("status carries no gossip_state".to_owned()),
    }
    match status.node_id.as_deref() {
        Some(node_id) => match node_holds_bundle_pull(&evidence.anchor_list_output, node_id) {
            Ok(true) => expected.push(("tcp", ANCHOR_PULL_ADDR.to_owned())),
            Ok(false) => {}
            Err(why) => reasons.push(format!("anchor capability cannot be determined: {why}")),
        },
        None => reasons.push("status carries no node_id".to_owned()),
    }

    // ── Compare with what is actually listening ─────────────────────────
    match parse_rustynetd_listeners(&evidence.ss_output) {
        Err(why) => reasons.push(why),
        Ok(observed) => {
            let mut remaining: Vec<&RustynetdListener> = observed.iter().collect();
            for (proto, addr) in &expected {
                if let Some(position) = remaining
                    .iter()
                    .position(|l| l.proto == *proto && l.local_addr == *addr)
                {
                    remaining.remove(position);
                } else {
                    reasons.push(format!("expected listener missing: {proto} {addr}"));
                }
            }
            for extra in remaining {
                reasons.push(format!("unexpected rustynetd listener: {}", extra.raw));
            }
        }
    }

    // ── CS3 gossip scope table (optional) ───────────────────────────────
    if options.expect_gossip_scope_table {
        match evidence.gossip_scope_table_output.as_deref() {
            None => reasons.push("gossip scope table was not captured".to_owned()),
            Some(text) => {
                if let Some(why) = gossip_scope_table_defect(text) {
                    reasons.push(why);
                }
            }
        }
    }

    // ── Active underlay probe ───────────────────────────────────────────
    let probe_text = match evidence.underlay_probe {
        None => "skipped".to_owned(),
        Some(probe) => {
            // Positive control FIRST: if sshd (tcp/22) did not answer, the
            // probe path is broken and every `no_answer` below is vacuous.
            match probe.tcp_positive_control {
                ProbeOutcome::Answered => {}
                ProbeOutcome::NoAnswer => reasons.push(
                    "underlay probe: tcp/22 positive control did not answer — the probe harness is not reaching this node, so the no_answer results are vacuous"
                        .to_owned(),
                ),
                ProbeOutcome::Inconclusive => reasons.push(
                    "underlay probe: tcp/22 positive control was inconclusive — the probe harness is not reaching this node, so the no_answer results are vacuous"
                        .to_owned(),
                ),
            }
            for (name, outcome) in [
                ("tcp/51822", probe.tcp_pull),
                ("udp/51821", probe.udp_gossip),
            ] {
                match outcome {
                    ProbeOutcome::NoAnswer => {}
                    ProbeOutcome::Answered => reasons.push(format!(
                        "underlay probe: {name} answered from the underlay address"
                    )),
                    ProbeOutcome::Inconclusive => {
                        reasons.push(format!("underlay probe: {name} was inconclusive"));
                    }
                }
            }
            format!(
                "tcp_pull={:?} udp_gossip={:?} tcp_positive_control={:?}",
                probe.tcp_pull, probe.udp_gossip, probe.tcp_positive_control
            )
        }
    };

    HostVerdict {
        label: evidence.label.clone(),
        pass: reasons.is_empty(),
        reasons,
        probe: probe_text,
    }
}

/// Same textual priority pin as `phase10`'s `plan_gossip_scope`: the text
/// after `priority` up to `;`, whitespace-stripped, must end in `-10` (real
/// nft 1.0.9 prints `priority filter - 10`). Catches drift to `0`, `10`,
/// `-100` and a missing priority token.
fn gossip_scope_header_priority_ok(line: &str) -> bool {
    let Some(index) = line.find("priority") else {
        return false;
    };
    let rest = &line[index + "priority".len()..];
    let rest = rest.split(';').next().unwrap_or("");
    rest.replace(' ', "").ends_with("-10")
}

/// `None` when the listing holds exactly an accept-policy input chain (at the
/// reviewed `-10` priority) with the reviewed loopback accept followed by the
/// tunnel-scope drop for the tunnel interface `rustynet0` (CS4 fix: the pin
/// is the tunnel interface NAME, and this deployment's tunnel is `rustynet0`
/// — an `!= "eth0"` or other interface is drift, not a valid variant), and
/// nothing else.
fn gossip_scope_table_defect(listing: &str) -> Option<String> {
    let lines: Vec<String> = listing
        .lines()
        .map(|l| l.replace('"', "").trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    if !lines
        .iter()
        .any(|l| l.starts_with("table inet ") && l.contains(GOSSIP_SCOPE_TABLE))
    {
        return Some(format!(
            "gossip scope table {GOSSIP_SCOPE_TABLE} is missing"
        ));
    }
    let header_ok = lines.iter().any(|l| {
        l.starts_with("type filter hook input")
            && l.contains("policy accept")
            && gossip_scope_header_priority_ok(l)
    });
    if !header_ok {
        return Some(
            "gossip scope chain is not an accept-policy input hook at priority -10".to_owned(),
        );
    }
    let rules: Vec<&String> = lines
        .iter()
        .filter(|l| {
            !(l.starts_with("table ")
                || l.starts_with("chain ")
                || l.starts_with("type ")
                || l.as_str() == "}")
        })
        .collect();
    let port = GOSSIP_PORT;
    const PINNED_TUNNEL_IFACE: &str = "rustynet0";
    let accept = format!("udp dport {port} iifname lo accept");
    let expected_drop = format!("udp dport {port} iifname != {PINNED_TUNNEL_IFACE} drop");
    if rules.len() != 2 || rules[0].as_str() != accept || rules[1].as_str() != expected_drop {
        return Some(format!(
            "gossip scope chain does not hold exactly the reviewed pair pinned to {PINNED_TUNNEL_IFACE}: {rules:?}"
        ));
    }
    None
}

/// CS4 fix (second-eyes F1): defects in the SHIPPED control-surface report
/// that must fail the opt-in verdict even when the expected listener set is
/// perfect. The opt-in check never replaces the shipped one: the daemon
/// socket, helper socket and remote-underlay-DNS checks stay load-bearing.
///
/// Fail closed: a missing checks object, a missing aggregate, a missing host
/// or a missing per-host check is a defect, not a pass. The shipped
/// aggregates are `.all()` over the captured hosts and are therefore
/// vacuously true on a report with no hosts, so a report with no host
/// evidence is itself a defect and every captured host label must carry its
/// own `daemon_socket_secure`/`helper_socket_secure` pass.
///
/// `report` is the PRIMARY report JSON as written by
/// `execute_ops_write_live_linux_control_surface_report`; `host_labels` are
/// the labels captured by the same live-lab run.
pub fn shipped_check_gate_defects<S: AsRef<str>>(report: &Value, host_labels: &[S]) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    match report.get("checks") {
        None => defects.push("shipped report carries no checks object".to_owned()),
        Some(checks) => {
            for name in ["all_daemon_sockets_secure", "all_helper_sockets_secure"] {
                if checks.get(name).and_then(Value::as_str) != Some("pass") {
                    defects.push(format!("shipped check {name} is not \"pass\""));
                }
            }
            match checks
                .get("remote_underlay_dns_probe_blocked")
                .and_then(Value::as_str)
            {
                Some("pass") | Some("skipped") => {}
                Some("fail") => defects
                    .push("shipped check remote_underlay_dns_probe_blocked is \"fail\"".to_owned()),
                Some(other) => defects.push(format!(
                    "shipped check remote_underlay_dns_probe_blocked has unexpected value {other:?}"
                )),
                None => defects
                    .push("shipped report carries no remote_underlay_dns_probe_blocked".to_owned()),
            }
        }
    }
    if host_labels.is_empty() {
        defects.push(
            "shipped report carries no host evidence (its aggregate checks would be vacuously true)"
                .to_owned(),
        );
    }
    for label in host_labels {
        let label: &str = label.as_ref();
        let Some(host) = report.get("hosts").and_then(|hosts| hosts.get(label)) else {
            defects.push(format!("shipped report is missing host {label:?}"));
            continue;
        };
        for name in ["daemon_socket_secure", "helper_socket_secure"] {
            if host
                .get("checks")
                .and_then(|checks| checks.get(name))
                .and_then(Value::as_str)
                != Some("pass")
            {
                defects.push(format!(
                    "host {label:?}: shipped check {name} is not \"pass\""
                ));
            }
        }
    }
    defects
}

/// Aggregate report body (stable JSON shape for the opt-in report).
pub fn render_report(
    hosts: &[HostVerdict],
    dns_bind_addr: &str,
    options: ExpectedSetOptions,
    captured_at_unix: u64,
) -> Value {
    let all_pass = !hosts.is_empty() && hosts.iter().all(|h| h.pass);
    let mut per_host = serde_json::Map::new();
    for host in hosts {
        per_host.insert(
            host.label.clone(),
            json!({ "pass": host.pass, "reasons": host.reasons, "underlay_probe": host.probe }),
        );
    }
    json!({
        "phase": "phase10",
        "mode": "live_linux_control_surface_expected_listener_set",
        "evidence_mode": "measured",
        "opt_in": true,
        "owner_approval_required": "this report redefines the control-surface check; the shipped check is unchanged",
        "captured_at_unix": captured_at_unix,
        "status": if all_pass { "pass" } else { "fail" },
        "dns_bind_addr": dns_bind_addr,
        "expect_gossip_scope_table": options.expect_gossip_scope_table,
        "hosts": per_host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS: &str = "127.0.0.1:53535";

    fn line(proto: &str, local: &str) -> String {
        let state = if proto == "tcp" { "LISTEN" } else { "UNCONN" };
        format!(
            "{proto} {state} 0      0      {local} 0.0.0.0:* users:((\"rustynetd\",pid=1,fd=4))"
        )
    }

    fn status(backend: &str, wg_addr: &str, gossip: &str) -> String {
        format!(
            "node_id=exit-1 node_role=admin transport_socket_identity_state={backend} \
             transport_socket_identity_local_addr={wg_addr} gossip_state={gossip}"
        )
    }

    const USERSPACE: &str = "authoritative_backend_shared_transport";
    const KERNEL: &str = "blocked_backend_opaque_socket";

    fn evidence(ss: &[String], status_text: String, anchor: bool) -> HostEvidence {
        HostEvidence {
            label: "exit".to_owned(),
            ss_output: ss.join("\n"),
            status_text,
            rustynet0_addr_output: "3: rustynet0    inet 100.64.0.1/32 scope global rustynet0\n"
                .to_owned(),
            anchor_list_output: if anchor {
                "exit-1 capabilities=anchor,anchor.bundle_pull\n".to_owned()
            } else {
                "other-1 capabilities=anchor,anchor.bundle_pull\n".to_owned()
            },
            gossip_scope_table_output: None,
            underlay_probe: Some(UnderlayProbe {
                tcp_pull: ProbeOutcome::NoAnswer,
                udp_gossip: ProbeOutcome::NoAnswer,
                // The default fixture probe ran against a node whose sshd
                // answered: the harness demonstrably works.
                tcp_positive_control: ProbeOutcome::Answered,
            }),
        }
    }

    const NO_TABLE: ExpectedSetOptions = ExpectedSetOptions {
        expect_gossip_scope_table: false,
    };

    fn healthy_userspace_anchor() -> HostEvidence {
        evidence(
            &[
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "127.0.0.1:51822"),
            ],
            status(USERSPACE, "0.0.0.0:51820", "active"),
            true,
        )
    }

    fn verdict(ev: &HostEvidence) -> HostVerdict {
        evaluate_host(ev, DNS, NO_TABLE)
    }

    #[test]
    fn healthy_userspace_anchor_node_passes() {
        let v = verdict(&healthy_userspace_anchor());
        assert!(v.pass, "{:?}", v.reasons);
    }

    #[test]
    fn healthy_userspace_non_anchor_and_kernel_nodes_pass() {
        // userspace, not an anchor, gossip active: no TCP.
        let ev = evidence(
            &[
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
            ],
            status(USERSPACE, "0.0.0.0:51820", "active"),
            false,
        );
        assert!(verdict(&ev).pass);
        // kernel backend: no WireGuard socket at all.
        let ev = evidence(
            &[line("udp", DNS), line("udp", "100.64.0.1:51821")],
            status(KERNEL, "none", "active"),
            false,
        );
        assert!(verdict(&ev).pass, "{:?}", verdict(&ev).reasons);
        // gossip not active: no gossip socket.
        let ev = evidence(
            &[line("udp", DNS)],
            status(KERNEL, "none", "unconfigured"),
            false,
        );
        assert!(verdict(&ev).pass);
    }

    fn assert_fails(ev: &HostEvidence, needle: &str) {
        let v = verdict(ev);
        assert!(!v.pass, "expected failure containing {needle:?}");
        assert!(
            v.reasons.iter().any(|r| r.contains(needle)),
            "{needle:?} not in {:?}",
            v.reasons
        );
    }

    #[test]
    fn each_deviation_fails_closed() {
        let base = healthy_userspace_anchor();
        let with = |ss: Vec<String>| HostEvidence {
            ss_output: ss.join("\n"),
            ..base.clone()
        };
        // gossip regressed to a wildcard bind (the original CS1 bug)
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "0.0.0.0:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "expected listener missing: udp 100.64.0.1:51821",
        );
        // ... and the wildcard itself is flagged as unexpected
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "0.0.0.0:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "unexpected rustynetd listener",
        );
        // missing resolver
        assert_fails(
            &with(vec![
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "expected listener missing: udp 127.0.0.1:53535",
        );
        // second wildcard
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "0.0.0.0:40000"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "unexpected rustynetd listener",
        );
        // duplicated product socket
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "unexpected rustynetd listener",
        );
        // anchor pull listener present but not on loopback
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "0.0.0.0:51822"),
            ]),
            "expected listener missing: tcp 127.0.0.1:51822",
        );
        // anchor missing its pull listener
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
            ]),
            "expected listener missing: tcp 127.0.0.1:51822",
        );
        // userspace WG socket not where the daemon says it is
        assert_fails(
            &with(vec![
                line("udp", DNS),
                line("udp", "0.0.0.0:51999"),
                line("udp", "100.64.0.1:51821"),
                line("tcp", "127.0.0.1:51822"),
            ]),
            "expected listener missing: udp 0.0.0.0:51820",
        );
    }

    #[test]
    fn non_anchor_with_the_pull_listener_and_kernel_with_a_wg_socket_fail() {
        let mut ev = healthy_userspace_anchor();
        ev.anchor_list_output = "other-1 capabilities=anchor.bundle_pull\n".to_owned();
        assert_fails(&ev, "unexpected rustynetd listener");
        // kernel backend must NOT show a rustynetd WG socket
        let ev = evidence(
            &[
                line("udp", DNS),
                line("udp", "0.0.0.0:51820"),
                line("udp", "100.64.0.1:51821"),
            ],
            status(KERNEL, "none", "active"),
            false,
        );
        assert_fails(&ev, "unexpected rustynetd listener");
        // gossip socket while gossip is not active
        let ev = evidence(
            &[line("udp", DNS), line("udp", "100.64.0.1:51821")],
            status(KERNEL, "none", "unconfigured"),
            false,
        );
        assert_fails(&ev, "unexpected rustynetd listener");
    }

    #[test]
    fn unparsable_or_missing_inputs_fail() {
        let base = healthy_userspace_anchor();
        // unknown backend
        let ev = HostEvidence {
            status_text: status("something_new", "none", "active"),
            ..base.clone()
        };
        assert_fails(&ev, "wireguard backend cannot be determined");
        // no status at all
        let ev = HostEvidence {
            status_text: String::new(),
            ..base.clone()
        };
        assert_fails(&ev, "cannot be determined");
        // garbage rustynetd line
        let ev = HostEvidence {
            ss_output: "rustynetd garbage".to_owned(),
            ..base.clone()
        };
        assert_fails(&ev, "unparsable rustynetd listener line");
        // gossip active but rustynet0 has no IPv4
        let ev = HostEvidence {
            rustynet0_addr_output: String::new(),
            ..base.clone()
        };
        assert_fails(&ev, "rustynet0 has no IPv4");
        // empty anchor list capture
        let ev = HostEvidence {
            anchor_list_output: String::new(),
            ..base
        };
        assert_fails(&ev, "anchor capability cannot be determined");
    }

    #[test]
    fn underlay_probe_must_prove_no_answer() {
        for (tcp, udp, needle) in [
            (
                ProbeOutcome::Answered,
                ProbeOutcome::NoAnswer,
                "tcp/51822 answered",
            ),
            (
                ProbeOutcome::NoAnswer,
                ProbeOutcome::Answered,
                "udp/51821 answered",
            ),
            (
                ProbeOutcome::Inconclusive,
                ProbeOutcome::NoAnswer,
                "tcp/51822 was inconclusive",
            ),
        ] {
            let mut ev = healthy_userspace_anchor();
            ev.underlay_probe = Some(UnderlayProbe {
                tcp_pull: tcp,
                udp_gossip: udp,
                tcp_positive_control: ProbeOutcome::Answered,
            });
            assert_fails(&ev, needle);
        }
        // no probe host: reported as skipped, not as a pass of the probe.
        let mut ev = healthy_userspace_anchor();
        ev.underlay_probe = None;
        let v = verdict(&ev);
        assert!(v.pass);
        assert_eq!(v.probe, "skipped");
        assert_eq!(ProbeOutcome::parse("answered\n"), ProbeOutcome::Answered);
        assert_eq!(ProbeOutcome::parse("no_answer"), ProbeOutcome::NoAnswer);
        assert_eq!(
            ProbeOutcome::parse("tool_missing"),
            ProbeOutcome::Inconclusive
        );
        assert_eq!(ProbeOutcome::parse(""), ProbeOutcome::Inconclusive);
    }

    #[test]
    fn underlay_probe_without_a_working_positive_control_fails_even_when_silent() {
        // CS4 fix (F3): `timeout` missing / no /dev/tcp support makes every
        // probe print no_answer. The tcp/22 (sshd) control must answer, else
        // the verdict fails CLOSED even though both real probes were silent.
        for control in [ProbeOutcome::NoAnswer, ProbeOutcome::Inconclusive] {
            let mut ev = healthy_userspace_anchor();
            ev.underlay_probe = Some(UnderlayProbe {
                tcp_pull: ProbeOutcome::NoAnswer,
                udp_gossip: ProbeOutcome::NoAnswer,
                tcp_positive_control: control,
            });
            assert_fails(&ev, "tcp/22 positive control");
            // The probe string carries the control outcome for the report.
            let v = verdict(&ev);
            assert!(
                v.probe.contains("tcp_positive_control"),
                "probe summary must name the control: {}",
                v.probe
            );
        }
        // Control answered + both probes silent: the ONLY passing shape.
        let mut ev = healthy_userspace_anchor();
        ev.underlay_probe = Some(UnderlayProbe {
            tcp_pull: ProbeOutcome::NoAnswer,
            udp_gossip: ProbeOutcome::NoAnswer,
            tcp_positive_control: ProbeOutcome::Answered,
        });
        assert!(verdict(&ev).pass);
    }

    #[test]
    fn gossip_scope_table_requirement() {
        let good = "table inet rustynet_svc_gossip {\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n\t\tudp dport 51821 iifname \"lo\" accept\n\t\tudp dport 51821 iifname != \"rustynet0\" drop\n\t}\n}\n";
        let opts = ExpectedSetOptions {
            expect_gossip_scope_table: true,
        };
        let mut ev = healthy_userspace_anchor();
        ev.gossip_scope_table_output = Some(good.to_owned());
        assert!(evaluate_host(&ev, DNS, opts).pass);
        // not captured / missing / extra rule / wrong policy / drop to lo
        for (bad, needle) in [
            (None, "was not captured"),
            (Some(String::new()), "is missing"),
            (
                Some(good.replace("\t}\n}\n", "\t\tudp dport 51821 accept\n\t}\n}\n")),
                "reviewed pair",
            ),
            (
                Some(good.replace("policy accept", "policy drop")),
                "accept-policy input",
            ),
            (
                Some(good.replace("!= \"rustynet0\"", "!= \"lo\"")),
                "reviewed pair",
            ),
            // CS4 fix (F2): the pin is the tunnel interface `rustynet0`; a
            // drop for any other interface is drift, not a valid variant.
            (
                Some(good.replace("!= \"rustynet0\"", "!= \"eth0\"")),
                "pinned to rustynet0",
            ),
            // CS4 fix (nit): hook-priority drift is caught, mirroring
            // phase10's plan_gossip_scope.
            (
                Some(good.replace("priority filter - 10", "priority filter 0")),
                "priority -10",
            ),
            (
                Some(good.replace("priority filter - 10; ", "")),
                "priority -10",
            ),
        ] {
            ev.gossip_scope_table_output = bad;
            let v = evaluate_host(&ev, DNS, opts);
            assert!(!v.pass);
            assert!(
                v.reasons.iter().any(|r| r.contains(needle)),
                "{needle}: {:?}",
                v.reasons
            );
        }
    }

    // ── CS4 fix (F1): the verdict also gates on the SHIPPED report ────────

    /// Primary-report shape (subset the gate reads) as written by
    /// `execute_ops_write_live_linux_control_surface_report`.
    fn shipped_report(
        all_daemon: &str,
        all_helper: &str,
        dns_probe: &str,
        hosts: &[(&str, &str, &str)],
    ) -> Value {
        let mut hosts_map = serde_json::Map::new();
        for (label, daemon, helper) in hosts {
            hosts_map.insert(
                (*label).to_owned(),
                json!({ "checks": { "daemon_socket_secure": daemon, "helper_socket_secure": helper } }),
            );
        }
        json!({
            "status": "pass",
            "checks": {
                "all_daemon_sockets_secure": all_daemon,
                "all_helper_sockets_secure": all_helper,
                "no_rustynet_tcp_listeners": "pass",
                "rustynet_udp_loopback_only": "pass",
                "remote_underlay_dns_probe_blocked": dns_probe,
            },
            "hosts": Value::Object(hosts_map),
        })
    }

    #[test]
    fn shipped_check_gate_accepts_a_healthy_primary_report() {
        let report = shipped_report("pass", "pass", "pass", &[("exit", "pass", "pass")]);
        assert!(shipped_check_gate_defects(&report, &["exit"]).is_empty());
        // A skipped remote-DNS probe is not a failure (the probe is
        // environment-dependent), but a failed one is.
        let report = shipped_report("pass", "pass", "skipped", &[("exit", "pass", "pass")]);
        assert!(shipped_check_gate_defects(&report, &["exit"]).is_empty());
    }

    #[test]
    fn shipped_check_gate_fails_closed_on_every_deviation() {
        let healthy = shipped_report("pass", "pass", "pass", &[("exit", "pass", "pass")]);
        // A failing aggregate.
        let report = shipped_report("fail", "pass", "pass", &[("exit", "pass", "pass")]);
        let defects = shipped_check_gate_defects(&report, &["exit"]);
        assert!(
            defects
                .iter()
                .any(|d| d.contains("all_daemon_sockets_secure"))
        );
        let report = shipped_report("pass", "fail", "pass", &[("exit", "pass", "pass")]);
        assert!(
            shipped_check_gate_defects(&report, &["exit"])
                .iter()
                .any(|d| d.contains("all_helper_sockets_secure"))
        );
        // A failing remote-DNS probe.
        let report = shipped_report("pass", "pass", "fail", &[("exit", "pass", "pass")]);
        assert!(
            shipped_check_gate_defects(&report, &["exit"])
                .iter()
                .any(|d| d.contains("remote_underlay_dns_probe_blocked"))
        );
        // An unexpected aggregate value (not pass/fail/skipped).
        let report = shipped_report("pass", "pass", "banana", &[("exit", "pass", "pass")]);
        assert!(
            shipped_check_gate_defects(&report, &["exit"])
                .iter()
                .any(|d| d.contains("banana"))
        );
        // A per-host socket failure despite green aggregates.
        let report = shipped_report("pass", "pass", "pass", &[("exit", "pass", "fail")]);
        assert!(
            shipped_check_gate_defects(&report, &["exit"])
                .iter()
                .any(|d| d.contains("helper_socket_secure") && d.contains("exit"))
        );
        // A host label missing from the report entirely.
        assert!(
            shipped_check_gate_defects(&healthy, &["ghost"])
                .iter()
                .any(|d| d.contains("missing host"))
        );
        // No host evidence at all: the aggregates would be vacuously true.
        let defects = shipped_check_gate_defects(&healthy, &[] as &[&str]);
        assert!(defects.iter().any(|d| d.contains("no host evidence")));
        // No checks object / malformed report.
        let defects = shipped_check_gate_defects(&json!({}), &["exit"]);
        assert!(defects.iter().any(|d| d.contains("no checks object")));
        assert!(defects.iter().any(|d| d.contains("missing host")));
    }

    #[test]
    fn a_bad_socket_mode_fails_the_gate_even_with_a_perfect_listener_set() {
        // The reviewer's exact scenario: the expected listener set is perfect
        // (healthy fixture passes) but the shipped daemon-socket check fails
        // (bad file mode). The combined verdict must be FAIL.
        let ev = healthy_userspace_anchor();
        let host_verdict = evaluate_host(&ev, DNS, NO_TABLE);
        assert!(host_verdict.pass);
        let report = shipped_report("fail", "pass", "pass", &[("exit", "fail", "pass")]);
        let defects =
            shipped_check_gate_defects(&report, std::slice::from_ref(&host_verdict.label));
        assert!(
            !defects.is_empty(),
            "a perfect listener set must not mask a shipped-check failure"
        );
    }

    #[test]
    fn parsers_cover_real_shapes() {
        let st = parse_status(
            "node_id=a transport_socket_identity_state=authoritative_backend_shared_transport \
             transport_socket_identity_local_addr=0.0.0.0:51820 gossip_state=active",
        );
        assert_eq!(
            st.backend,
            WireguardBackend::Userspace {
                local_addr: "0.0.0.0:51820".to_owned()
            }
        );
        assert_eq!(
            parse_rustynet0_ipv4("5: rustynet0    inet 100.64.0.9/32 scope global rustynet0\n"),
            Some("100.64.0.9".to_owned())
        );
        assert_eq!(parse_rustynet0_ipv4("garbage"), None);
        assert_eq!(parse_rustynet0_ipv4("1: x inet 999.1.1.1/32 scope"), None);
        // `*:port` wildcard spelling normalises
        let listeners = parse_rustynetd_listeners(
            "udp UNCONN 0 0 *:51820 *:* users:((\"rustynetd\",pid=1,fd=6))",
        )
        .expect("parse");
        assert_eq!(listeners[0].local_addr, "0.0.0.0:51820");
        // capability CSV match is exact, never a substring
        assert_eq!(
            node_holds_bundle_pull("n capabilities=anchor.bundle_pull_v2\n", "n"),
            Ok(false)
        );
        assert_eq!(
            node_holds_bundle_pull("n capabilities=anchor,anchor.bundle_pull\n", "n"),
            Ok(true)
        );
    }

    // ── strictness vs the shipped check ─────────────────────────────────

    /// Mirror of the shipped listener logic in
    /// `execute_ops_write_live_linux_control_surface_report`: returns
    /// `(tcp_ok, udp_ok)`. Kept honest by the differential test below.
    fn legacy_listener_verdict(ss_output: &str, allowed_udp: &str) -> (bool, bool) {
        let mut tcp_ok = true;
        let mut udp_ok = true;
        for line in ss_output.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if !line.contains("rustynetd") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                tcp_ok = false;
                udp_ok = false;
                continue;
            }
            let proto = parts[0];
            let local = parts[4];
            if proto.starts_with("tcp") {
                tcp_ok = false;
            } else if proto.starts_with("udp") {
                if local != allowed_udp {
                    udp_ok = false;
                }
            } else {
                udp_ok = false;
            }
        }
        (tcp_ok, udp_ok)
    }

    /// Universe of listener lines (rustynetd and not).
    fn universe() -> Vec<(String, bool)> {
        let foreign = |proto: &str, local: &str, who: &str| {
            let state = if proto == "tcp" { "LISTEN" } else { "UNCONN" };
            format!("{proto} {state} 0 0 {local} 0.0.0.0:* users:((\"{who}\",pid=9,fd=3))")
        };
        vec![
            (line("udp", DNS), true),
            (line("udp", "0.0.0.0:51820"), true),
            (line("udp", "100.64.0.1:51821"), true),
            (line("udp", "0.0.0.0:51821"), true),
            (line("tcp", "127.0.0.1:51822"), true),
            (line("tcp", "0.0.0.0:51822"), true),
            (line("udp", "127.0.0.1:9999"), true),
            (line("udp", "0.0.0.0:40000"), true),
            (line("udp", "[::]:51820"), true),
            (foreign("tcp", "127.0.0.1:22", "sshd"), false),
            (foreign("udp", "0.0.0.0:68", "dhclient"), false),
        ]
    }

    #[test]
    fn the_legacy_mirror_agrees_with_the_shipped_report_writer() {
        use crate::ops_live_lab_orchestrator::{
            WriteLiveLinuxControlSurfaceReportConfig,
            execute_ops_write_live_linux_control_surface_report,
        };
        let dir = std::env::temp_dir().join(format!("rn-cs4-mirror-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let universe = universe();
        // A spread of subsets (full power set is 2^11; sample every 7th plus edges).
        for mask in (0u32..(1 << universe.len()))
            .step_by(7)
            .chain([0, (1 << universe.len()) - 1])
        {
            let lines: Vec<&str> = universe
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (l, _))| l.as_str())
                .collect();
            let text = lines.join("\n");
            std::fs::write(dir.join("n.daemon_socket.txt"), "socket|600|root|root\n").expect("w");
            std::fs::write(
                dir.join("n.helper_socket.txt"),
                "socket|660|root|rustynetd\n",
            )
            .expect("w");
            std::fs::write(dir.join("n.inet_listeners.txt"), &text).expect("w");
            std::fs::write(dir.join("n.managed_dns_state.txt"), "active\n").expect("w");
            let report = dir.join("r.json");
            let _ = execute_ops_write_live_linux_control_surface_report(
                WriteLiveLinuxControlSurfaceReportConfig {
                    report_path: report.clone(),
                    dns_bind_addr: DNS.to_owned(),
                    remote_dns_probe_status: "pass".to_owned(),
                    remote_dns_probe_output: "{}".to_owned(),
                    work_dir: dir.clone(),
                    host_labels: vec!["n".to_owned()],
                    captured_at_utc: "t".to_owned(),
                    captured_at_unix: 1,
                },
            )
            .expect("report");
            let body: Value =
                serde_json::from_str(&std::fs::read_to_string(&report).expect("read"))
                    .expect("json");
            let checks = &body["hosts"]["n"]["checks"];
            let (tcp_ok, udp_ok) = legacy_listener_verdict(&text, DNS);
            assert_eq!(
                checks["no_rustynet_tcp_listener"] == "pass",
                tcp_ok,
                "mask {mask}"
            );
            assert_eq!(
                checks["rustynet_udp_loopback_only"] == "pass",
                udp_ok,
                "mask {mask}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct Ctx {
        userspace: bool,
        gossip: bool,
        anchor: bool,
    }

    fn ctx_evidence(ctx: &Ctx, ss: &str) -> HostEvidence {
        let status_text = if ctx.userspace {
            status(
                USERSPACE,
                "0.0.0.0:51820",
                if ctx.gossip { "active" } else { "unconfigured" },
            )
        } else {
            status(
                KERNEL,
                "none",
                if ctx.gossip { "active" } else { "unconfigured" },
            )
        };
        let mut ev = evidence(&[], status_text, ctx.anchor);
        ev.ss_output = ss.to_owned();
        ev
    }

    /// The product-owned lines the new check is allowed to admit beyond the
    /// shipped definition, for a given node context.
    fn admitted(ctx: &Ctx) -> Vec<String> {
        let mut lines = Vec::new();
        if ctx.userspace {
            lines.push(line("udp", "0.0.0.0:51820"));
        }
        if ctx.gossip {
            lines.push(line("udp", "100.64.0.1:51821"));
        }
        if ctx.anchor {
            lines.push(line("tcp", "127.0.0.1:51822"));
        }
        lines
    }

    #[test]
    fn expected_set_is_strictly_stricter_than_the_shipped_check_except_the_admitted_lines() {
        let universe = universe();
        let ctxs: Vec<Ctx> = (0..8)
            .map(|bits| Ctx {
                userspace: bits & 1 != 0,
                gossip: bits & 2 != 0,
                anchor: bits & 4 != 0,
            })
            .collect();
        let mut new_passes = 0usize;
        for ctx in &ctxs {
            let admitted_lines = admitted(ctx);
            for mask in 0u32..(1 << universe.len()) {
                let selected: Vec<String> = universe
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, (l, _))| l.clone())
                    .collect();
                let text = selected.join("\n");
                let new_pass = {
                    let mut ev = ctx_evidence(ctx, &text);
                    ev.underlay_probe = None;
                    evaluate_host(&ev, DNS, NO_TABLE).pass
                };
                // What the shipped check says about the same node once the
                // admitted product-owned lines are set aside.
                let residual: Vec<&String> = selected
                    .iter()
                    .filter(|l| !admitted_lines.contains(l))
                    .collect();
                let residual_text = residual
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let (legacy_tcp, legacy_udp) = legacy_listener_verdict(&residual_text, DNS);
                let legacy_residual_pass = legacy_tcp && legacy_udp;

                // (A) strictness: the new check never passes a node the shipped
                // check would reject for any reason other than an admitted line.
                if new_pass {
                    new_passes += 1;
                    assert!(
                        legacy_residual_pass,
                        "new check passed a node the shipped check rejects for a non-admitted reason: ctx userspace={} gossip={} anchor={} set={selected:?}",
                        ctx.userspace, ctx.gossip, ctx.anchor
                    );
                    // (B) and it demands the positive expectations the shipped
                    // check never had: the resolver and every admitted line.
                    assert!(selected.contains(&line("udp", DNS)));
                    for needed in &admitted_lines {
                        assert!(selected.contains(needed), "missing {needed}");
                    }
                    // (C) exactness: no duplicates, no extras.
                    let rustynetd_lines =
                        selected.iter().filter(|l| l.contains("rustynetd")).count();
                    assert_eq!(rustynetd_lines, 1 + admitted_lines.len());
                }
                // (D) monotone: adding any rustynetd line outside the admitted
                // set to a passing node makes it fail.
                if new_pass {
                    for (extra, is_rustynetd) in &universe {
                        if *is_rustynetd && !selected.contains(extra) {
                            let mut with_extra = selected.clone();
                            with_extra.push(extra.clone());
                            let mut ev = ctx_evidence(ctx, &with_extra.join("\n"));
                            ev.underlay_probe = None;
                            assert!(
                                !evaluate_host(&ev, DNS, NO_TABLE).pass,
                                "adding {extra} must break a passing node"
                            );
                        }
                    }
                }
            }
        }
        assert!(
            new_passes >= ctxs.len(),
            "each node context has a passing set"
        );
    }

    #[test]
    fn nodes_the_shipped_check_passes_can_fail_the_new_check_but_never_the_reverse() {
        // The shipped-check-clean listener set (DNS only) fails the new check
        // wherever the node is supposed to be listening on more (a userspace
        // node with no WG socket, an active gossip node with no gossip
        // socket, an anchor with no pull socket): the shipped check has no
        // positive expectations, the new one does.
        let only_dns = line("udp", DNS);
        assert_eq!(legacy_listener_verdict(&only_dns, DNS), (true, true));
        for (userspace, gossip, anchor, new_passes) in [
            (false, false, false, true),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
        ] {
            let ctx = Ctx {
                userspace,
                gossip,
                anchor,
            };
            let mut ev = ctx_evidence(&ctx, &only_dns);
            ev.underlay_probe = None;
            assert_eq!(evaluate_host(&ev, DNS, NO_TABLE).pass, new_passes);
        }
    }

    #[test]
    fn report_shape_is_labelled_opt_in_and_requires_every_host() {
        let ok = HostVerdict {
            label: "a".into(),
            pass: true,
            reasons: vec![],
            probe: "skipped".into(),
        };
        let bad = HostVerdict {
            label: "b".into(),
            pass: false,
            reasons: vec!["x".into()],
            probe: "skipped".into(),
        };
        let report = render_report(&[ok.clone(), bad], DNS, NO_TABLE, 1);
        assert_eq!(report["status"], "fail");
        assert_eq!(report["opt_in"], true);
        assert!(report["owner_approval_required"].as_str().is_some());
        assert_eq!(
            report["mode"],
            "live_linux_control_surface_expected_listener_set"
        );
        assert_eq!(render_report(&[ok], DNS, NO_TABLE, 1)["status"], "pass");
        // zero hosts never passes
        assert_eq!(render_report(&[], DNS, NO_TABLE, 1)["status"], "fail");
    }
}
