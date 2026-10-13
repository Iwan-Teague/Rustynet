//! Best-effort per-node network diagnostics capture for the live lab.
//!
//! When a node's dataplane misbehaves (handshakes never complete, the
//! management path degrades after the killswitch engages) the existing failure
//! evidence is thin: a mesh IP, a tunnel list and a daemon reason. This module
//! snapshots the kernel and daemon state that actually explains those failures
//! — nftables, policy routing, WireGuard peers, neighbours, conntrack, the
//! tailscale peer path and recent daemon logs — into
//! `<report_dir>/logs/diag_<phase>_<alias>.txt`.
//!
//! Contract (harness-only, no product change):
//! * Best effort. Nothing here can change a stage outcome: every failure is
//!   recorded in the file as a `capture error: <what>` line and the function
//!   returns `()`.
//! * Every remote command is an argv run through the [`RemoteShellHost`] seam
//!   (each element single-quoted, no shell construction) and is individually
//!   bounded by a remote `timeout`.
//! * No key material. `wg show all` is used WITHOUT `dump` (the dump form
//!   prints private keys), any line mentioning a secret/token/authkey/
//!   passphrase/private/preshared key is dropped as defence in depth, and the
//!   tailscale status is reduced to a per-peer path summary (direct/relay, no
//!   addresses) rather than echoed raw.
//! * Addressing is scrubbed best-effort, not guaranteed: captured text passes
//!   through the overlay redaction set the ledger writers use
//!   ([`crate::vm_lab::OverlayRedaction`]), the inventory `dataplane_endpoint`
//!   addresses and the `ssh_allow_cidrs` single-host addresses (placeholders),
//!   and then a generic pass that replaces any remaining GLOBAL IPv4/IPv6
//!   literal with [`PUBLIC_IP_PLACEHOLDER`]. Private, CGNAT/tailnet,
//!   loopback, link-local and ULA addresses are kept because they are what
//!   explains routing state. Hostnames are not scrubbed beyond the overlay
//!   set. The files are created mode 0600 and live only under the report
//!   dir's `logs/`, never in a ledger.

use std::fmt::Write as _;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::load_dataplane_overrides;

/// Phase tag: immediately after `enforce_baseline_runtime` (pass or fail).
pub(crate) const PHASE_POST_ENFORCE: &str = "post-enforce";
/// Phase tag: a `mesh_status_validation` failure.
pub(crate) const PHASE_MESH_STATUS_FAILURE: &str = "mesh-status-failure";
/// Phase tag: a `traffic_test_matrix` failure.
pub(crate) const PHASE_TRAFFIC_MATRIX_FAILURE: &str = "traffic-matrix-failure";

/// Replacement for an inventory `dataplane_endpoint` address in captured text.
pub(crate) const DATAPLANE_PLACEHOLDER: &str = "<dataplane-endpoint>";
/// Replacement for an `ssh_allow_cidrs` single-host (management peer) address.
pub(crate) const MGMT_PEER_PLACEHOLDER: &str = "<mgmt-peer>";
/// Replacement for any other global IP literal in captured text.
pub(crate) const PUBLIC_IP_PLACEHOLDER: &str = "<public-ip>";

/// Node-side reachability/sudo probe run before the command list; a transport
/// failure here is reported as `capture error: ssh unreachable`.
const PROBE_ARGV: &[&str] = &["timeout", "10", "true"];

/// Per-command output cap (lines). Bounds the evidence file, not an error.
const MAX_LINES_PER_COMMAND: usize = 600;
/// Per-line cap (characters); nft rules and journal lines can be very long.
const MAX_LINE_CHARS: usize = 1000;
/// Workers used when capturing several nodes at once.
const CAPTURE_PARALLELISM: usize = 4;

/// Ports whose conntrack entries matter: tailscale (41641), WireGuard (51820)
/// and DERP/HTTPS (443).
const CONNTRACK_PORTS: &[&str] = &["41641", "51820", "443"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostProcess {
    /// Keep the output, capped at [`MAX_LINES_PER_COMMAND`].
    Raw,
    /// Keep only the last N lines.
    TailLines(usize),
    /// Keep only conntrack entries touching [`CONNTRACK_PORTS`].
    ConntrackPortFilter,
    /// Reduce `tailscale status --json` to the per-peer path summary.
    TailscalePeerSummary,
}

struct DiagCommand {
    label: &'static str,
    /// Always starts with `timeout <secs>` so each command is bounded on the
    /// node itself (the orchestrator's transport timeout is far looser).
    argv: &'static [&'static str],
    post: PostProcess,
    /// `timeout` exiting 124 is the EXPECTED end of a capture-window command
    /// (tcpdump stops at the window end with fewer than `-c` packets).
    timeout_is_expected: bool,
    /// A fixed-duration capture window (costs its full duration on every
    /// node); only taken for failure phases or dataplane-addressed nodes.
    window: bool,
}

const DIAG_COMMANDS: &[DiagCommand] = &[
    DiagCommand {
        label: "nft list ruleset",
        argv: &["timeout", "10", "nft", "list", "ruleset"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "ip rule",
        argv: &["timeout", "10", "ip", "rule", "show"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "ip route show table all",
        argv: &["timeout", "10", "ip", "route", "show", "table", "all"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    // NOT `wg show all dump`: the dump form prints private keys.
    DiagCommand {
        label: "wg show all",
        argv: &["timeout", "10", "wg", "show", "all"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "ip neigh",
        argv: &["timeout", "10", "ip", "neigh", "show"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "conntrack -S",
        argv: &["timeout", "10", "conntrack", "-S"],
        post: PostProcess::Raw,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "conntrack -L (ports 41641/51820/443)",
        argv: &["timeout", "10", "conntrack", "-L"],
        post: PostProcess::ConntrackPortFilter,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "tailscale status (peer paths)",
        argv: &["timeout", "10", "tailscale", "status", "--json"],
        post: PostProcess::TailscalePeerSummary,
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "journalctl rustynetd+tailscaled (last 10min, tail 150)",
        argv: &[
            "timeout",
            "15",
            "journalctl",
            "-u",
            "rustynetd",
            "-u",
            "tailscaled",
            "--since=-10min",
            "--no-pager",
            "-n",
            "150",
        ],
        post: PostProcess::TailLines(150),
        timeout_is_expected: false,
        window: false,
    },
    DiagCommand {
        label: "tcpdump 6s (udp 51820/41641)",
        argv: &[
            "timeout",
            "6",
            "tcpdump",
            "-ni",
            "any",
            "-c",
            "40",
            "udp port 51820 or udp port 41641",
        ],
        post: PostProcess::Raw,
        timeout_is_expected: true,
        window: true,
    },
];

/// Single-host (`/32` or `/128`) addresses in an `ssh_allow_cidrs` CSV. On a
/// tailnet-managed run these are the orchestrator's tailnet address(es).
pub(crate) fn single_host_cidrs(ssh_allow_cidrs: &str) -> Vec<std::net::IpAddr> {
    ssh_allow_cidrs
        .split(',')
        .filter_map(|entry| {
            let (addr, prefix) = entry.trim().split_once('/')?;
            let ip: std::net::IpAddr = addr.parse().ok()?;
            let full = if ip.is_ipv4() { "32" } else { "128" };
            (prefix == full).then_some(ip)
        })
        .collect()
}

/// True for an address worth scrubbing: not private, CGNAT/tailnet, loopback,
/// link-local, ULA, unspecified, multicast or broadcast/reserved.
fn is_global_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || cgnat
                || o[0] >= 240)
        }
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let ula = (seg0 & 0xfe00) == 0xfc00;
            let link_local = (seg0 & 0xffc0) == 0xfe80;
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || ula || link_local)
        }
    }
}

/// Replace every global IPv4/IPv6 literal in `text` with
/// [`PUBLIC_IP_PLACEHOLDER`]. Tokenises maximal runs of address characters, so
/// `a.b.c.d:port` and `addr/len` keep their suffixes.
fn scrub_global_ip_literals(text: &str) -> String {
    fn rewrite(
        text: &str,
        is_token_char: impl Fn(char) -> bool,
        accept: impl Fn(&str) -> Option<std::net::IpAddr>,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        let mut token = String::new();
        let flush = |token: &mut String, out: &mut String| {
            if token.is_empty() {
                return;
            }
            // Trailing separators belong to the prose, not the literal.
            let trimmed = token.trim_end_matches(['.', ':']);
            let tail = &token[trimmed.len()..];
            match accept(trimmed) {
                Some(ip) if is_global_ip(&ip) => out.push_str(PUBLIC_IP_PLACEHOLDER),
                _ => out.push_str(trimmed),
            }
            out.push_str(tail);
            token.clear();
        };
        for c in text.chars() {
            if is_token_char(c) {
                token.push(c);
            } else {
                flush(&mut token, &mut out);
                out.push(c);
            }
        }
        flush(&mut token, &mut out);
        out
    }
    let v4 = rewrite(
        text,
        |c| c.is_ascii_digit() || c == '.',
        |t| {
            let parts: Vec<&str> = t.split('.').collect();
            (parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3))
                .then(|| {
                    t.parse::<std::net::Ipv4Addr>()
                        .ok()
                        .map(std::net::IpAddr::V4)
                })
                .flatten()
        },
    );
    rewrite(
        &v4,
        |c| c.is_ascii_hexdigit() || c == ':',
        |t| {
            (t.matches(':').count() >= 2)
                .then(|| {
                    t.parse::<std::net::Ipv6Addr>()
                        .ok()
                        .map(std::net::IpAddr::V6)
                })
                .flatten()
        },
    )
}

/// Replaces addressing that must not land in evidence text.
pub(crate) struct Scrubber {
    /// Inventory `dataplane_endpoint` addresses.
    dataplane: Vec<String>,
    /// `ssh_allow_cidrs` single-host addresses (the orchestrator's peer).
    mgmt_peers: Vec<String>,
    overlay: Option<crate::vm_lab::OverlayRedaction>,
    /// Aliases that declare a `dataplane_endpoint`.
    dataplane_aliases: Vec<String>,
}

impl Scrubber {
    /// Build the scrub set for a run: every inventory `dataplane_endpoint`
    /// address, the `ssh_allow_cidrs` single hosts, and the overlay redaction
    /// set the ledger writers use. Fails closed — a scrub set that cannot be
    /// built means diagnostics are withheld rather than written unscrubbed.
    pub(crate) fn for_run(ctx: &OrchestrationContext) -> Result<Self, String> {
        let overrides = load_dataplane_overrides(ctx.inventory_path.as_deref())
            .map_err(|e| format!("inventory dataplane overrides unavailable: {e}"))?;
        let overlay = crate::vm_lab::inventory_overlay_redaction()
            .map_err(|e| format!("overlay redaction set unavailable: {e}"))?;
        Ok(Self::new(
            overrides.values().map(ToString::to_string).collect(),
            single_host_cidrs(&ctx.ssh_allow_cidrs)
                .iter()
                .map(ToString::to_string)
                .collect(),
            overlay,
            overrides.keys().cloned().collect(),
        ))
    }

    pub(crate) fn new(
        dataplane: Vec<String>,
        mgmt_peers: Vec<String>,
        overlay: Option<crate::vm_lab::OverlayRedaction>,
        dataplane_aliases: Vec<String>,
    ) -> Self {
        Self {
            dataplane,
            mgmt_peers,
            overlay,
            dataplane_aliases,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_needles(needles: &[&str]) -> Self {
        Self::new(
            needles.iter().map(|n| (*n).to_owned()).collect(),
            Vec::new(),
            None,
            Vec::new(),
        )
    }

    fn is_dataplane_alias(&self, alias: &str) -> bool {
        self.dataplane_aliases.iter().any(|a| a == alias)
    }

    fn scrub(&self, text: &str) -> String {
        let mut out = match &self.overlay {
            Some(overlay) => overlay.scrub(text),
            None => text.to_owned(),
        };
        for (needles, placeholder) in [
            (&self.dataplane, DATAPLANE_PLACEHOLDER),
            (&self.mgmt_peers, MGMT_PEER_PLACEHOLDER),
        ] {
            for needle in needles {
                if !needle.is_empty() && out.contains(needle.as_str()) {
                    out = out.replace(needle.as_str(), placeholder);
                }
            }
        }
        scrub_global_ip_literals(&out)
    }
}

/// True when `value` is safe as a filename component (alias or phase).
pub(crate) fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Collapse newlines so a remote-controlled string cannot forge evidence lines.
fn single_line(s: &str) -> String {
    s.replace(['\n', '\r'], "\\n")
}

/// Lines that may carry key material: dropped wherever they appear.
fn is_secret_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "secret",
        "token",
        "authkey",
        "tskey-",
        "passphrase",
        "private",
        "preshared",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn push_error(out: &mut String, scrub: &Scrubber, what: &str, detail: &str) {
    let _ = writeln!(
        out,
        "capture error: {what}: {}",
        scrub.scrub(&single_line(detail))
    );
}

fn first_stderr_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no stderr)")
        .chars()
        .take(300)
        .collect()
}

/// Reduce `tailscale status --json` to the facts that explain a stranded or
/// degraded management path. Only path/health fields are kept: no keys, no
/// address lists.
fn summarize_tailscale_status(json_text: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json_text).map_err(|e| format!("not valid JSON: {e}"))?;
    let text = |v: &serde_json::Value, key: &str| -> String {
        v.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map_or_else(|| "-".to_owned(), single_line)
    };
    let flag = |v: &serde_json::Value, key: &str| -> String {
        v.get(key)
            .and_then(serde_json::Value::as_bool)
            .map_or_else(|| "?".to_owned(), |b| b.to_string())
    };
    let mut lines = vec![format!("backend_state={}", text(&value, "BackendState"))];
    if let Some(health) = value.get("Health").and_then(serde_json::Value::as_array) {
        for item in health.iter().filter_map(serde_json::Value::as_str) {
            lines.push(format!("health={}", single_line(item)));
        }
    }
    if let Some(me) = value.get("Self") {
        lines.push(format!(
            "self online={} relay={}",
            flag(me, "Online"),
            text(me, "Relay")
        ));
    }
    if let Some(peers) = value.get("Peer").and_then(serde_json::Value::as_object) {
        let mut peer_lines: Vec<String> = peers
            .values()
            .map(|p| {
                format!(
                    "peer host={} online={} active={} relay={} path={}",
                    text(p, "HostName"),
                    flag(p, "Online"),
                    flag(p, "Active"),
                    text(p, "Relay"),
                    // Direct vs relayed only: the endpoint address is not kept.
                    if text(p, "CurAddr") == "-" {
                        "relay"
                    } else {
                        "direct"
                    },
                )
            })
            .collect();
        peer_lines.sort();
        lines.extend(peer_lines);
    }
    Ok(lines)
}

/// Apply the per-command post-processing to the raw (lossy UTF-8) output.
fn post_process(post: PostProcess, raw: &str) -> Result<Vec<String>, String> {
    let lines = raw.lines().map(str::to_owned);
    Ok(match post {
        PostProcess::Raw => lines.collect(),
        PostProcess::TailLines(n) => {
            let all: Vec<String> = lines.collect();
            let skip = all.len().saturating_sub(n);
            all.into_iter().skip(skip).collect()
        }
        PostProcess::ConntrackPortFilter => lines
            .filter(|l| {
                CONNTRACK_PORTS
                    .iter()
                    .any(|p| l.contains(&format!("dport={p}")) || l.contains(&format!("sport={p}")))
            })
            .collect(),
        PostProcess::TailscalePeerSummary => summarize_tailscale_status(raw)?,
    })
}

/// Run the diagnostic command list over `shell` and render the evidence file.
/// Pure over the shell seam so the error-recording behaviour is unit-testable.
pub(crate) fn render_node_diagnostics(
    shell: &dyn RemoteShellHost,
    alias: &str,
    phase: &str,
    scrub: &Scrubber,
    include_window: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# node diagnostics");
    let _ = writeln!(out, "node: {alias}");
    let _ = writeln!(out, "phase: {phase}");

    // Reachability probe first: one bounded failure instead of ten slow ones.
    match shell.run_argv(PROBE_ARGV, &[], &[]) {
        Err(e) => {
            push_error(&mut out, scrub, "ssh unreachable", &e.to_string());
            return out;
        }
        Ok(status) if !status.is_success() => {
            push_error(
                &mut out,
                scrub,
                "remote exec probe failed",
                &format!("rc={}: {}", status.code, first_stderr_line(&status.stderr)),
            );
            return out;
        }
        Ok(_) => {}
    }

    for cmd in DIAG_COMMANDS.iter().filter(|c| include_window || !c.window) {
        let _ = writeln!(out, "== {} ==", cmd.label);
        let status = match shell.run_argv(cmd.argv, &[], &[]) {
            Ok(status) => status,
            Err(e) => {
                push_error(&mut out, scrub, cmd.label, &e.to_string());
                // A transport failure means later commands would only repeat
                // it, each burning a full transport timeout.
                let _ = writeln!(
                    out,
                    "capture error: remaining commands skipped after transport failure"
                );
                return out;
            }
        };
        let timed_out = status.code == 124;
        let window_end = timed_out && cmd.timeout_is_expected;
        if !status.is_success() && !window_end {
            let detail = if timed_out {
                "timed out before completing".to_owned()
            } else {
                let stderr = first_stderr_line(&status.stderr);
                let hint = if stderr.contains("not found") || status.code == 127 {
                    " (tool not installed?)"
                } else {
                    ""
                };
                format!("rc={}: {stderr}{hint}", status.code)
            };
            push_error(&mut out, scrub, cmd.label, &detail);
            continue;
        }
        if timed_out {
            let _ = writeln!(out, "note: capture window ended at its timeout");
        }
        let raw = String::from_utf8_lossy(&status.stdout);
        let lines = match post_process(cmd.post, &raw) {
            Ok(lines) => lines,
            Err(e) => {
                push_error(
                    &mut out,
                    scrub,
                    cmd.label,
                    &format!("unparseable output: {e}"),
                );
                continue;
            }
        };
        let mut kept = 0usize;
        let mut total = 0usize;
        for line in lines {
            total += 1;
            if is_secret_line(&line) || kept >= MAX_LINES_PER_COMMAND {
                continue;
            }
            kept += 1;
            let clipped: String = line
                .chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .take(MAX_LINE_CHARS)
                .collect();
            let _ = writeln!(out, "{}", scrub.scrub(&clipped));
        }
        if total == 0 {
            let _ = writeln!(out, "(no output)");
        } else if total > kept {
            let _ = writeln!(
                out,
                "(... {} line(s) withheld: cap or key-material filter)",
                total - kept
            );
        }
    }
    out
}

fn write_diag_file(ctx: &OrchestrationContext, phase: &str, alias: &str, body: &str) {
    let logs_dir = ctx.report_dir.join("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("node_diagnostics: cannot create logs dir: {e}");
        return;
    }
    let path = logs_dir.join(format!("diag_{phase}_{alias}.txt"));
    if let Err(e) = write_private_file(&path, body) {
        eprintln!("node_diagnostics: write failed for {alias}: {e}");
    }
}

/// Write `body` to `path`, creating it mode 0600 (raw node state, even scrubbed,
/// is operator-only) and narrowing a pre-existing file to 0600 as well.
fn write_private_file(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(body.as_bytes())
}

/// Capture diagnostics for one node into `logs/diag_<phase>_<alias>.txt`.
/// Best effort: never fails and never changes a stage outcome.
pub(crate) fn capture_node_diagnostics(ctx: &OrchestrationContext, alias: &str, phase: &str) {
    if !is_safe_component(alias) || !is_safe_component(phase) {
        eprintln!("node_diagnostics: skipped unsafe alias/phase {alias:?}/{phase:?}");
        return;
    }
    let mut header = String::new();
    let _ = writeln!(header, "# node diagnostics");
    let _ = writeln!(header, "node: {alias}");
    let _ = writeln!(header, "phase: {phase}");
    let Some(adapter) = ctx.adapters.get(alias) else {
        let _ = writeln!(header, "capture error: no adapter for node");
        write_diag_file(ctx, phase, alias, &header);
        return;
    };
    if adapter.platform() != VmGuestPlatform::Linux {
        let _ = writeln!(
            header,
            "capture skipped: diagnostics command list is Linux-only (platform {:?})",
            adapter.platform()
        );
        write_diag_file(ctx, phase, alias, &header);
        return;
    }
    let scrub = match Scrubber::for_run(ctx) {
        Ok(scrub) => scrub,
        Err(e) => {
            let _ = writeln!(
                header,
                "capture error: {}; diagnostics withheld rather than written unscrubbed",
                single_line(&e)
            );
            write_diag_file(ctx, phase, alias, &header);
            return;
        }
    };
    let body = match adapter.shell_host() {
        Ok(shell) => {
            // The fixed-length capture window is only worth its cost when
            // something already failed, or the node is dataplane-addressed.
            let include_window = phase != PHASE_POST_ENFORCE || scrub.is_dataplane_alias(alias);
            render_node_diagnostics(shell.as_ref(), alias, phase, &scrub, include_window)
        }
        Err(e) => {
            push_error(
                &mut header,
                &scrub,
                "remote shell unavailable",
                &e.to_string(),
            );
            header
        }
    };
    write_diag_file(ctx, phase, alias, &body);
}

/// Capture diagnostics for every assigned node (bounded parallelism).
pub(crate) fn capture_all_nodes_diagnostics(ctx: &OrchestrationContext, phase: &str) {
    let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
    crate::vm_lab::orchestrator::parallel::bounded_parallel_map(
        &aliases,
        CAPTURE_PARALLELISM,
        |alias| capture_node_diagnostics(ctx, alias, phase),
    );
}

/// Shared test doubles: a scripted remote shell and a minimal Linux adapter
/// whose only live surfaces are `shell_host`, `enforce_runtime` and cleanup.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::context::OrchestrationContext;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
        ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::remote_shell::{
        RemoteExitStatus, RemoteShellError, RemoteShellHost, RemoteStat,
    };
    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use crate::vm_lab::{DaemonProbeOp, VmGuestPlatform};

    pub(crate) type Responder =
        dyn Fn(&[String]) -> Result<RemoteExitStatus, RemoteShellError> + Send + Sync;
    pub(crate) type EventLog = Arc<Mutex<Vec<String>>>;

    pub(crate) fn ok(stdout: &str) -> Result<RemoteExitStatus, RemoteShellError> {
        Ok(RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    pub(crate) fn rc(code: i32, stderr: &str) -> Result<RemoteExitStatus, RemoteShellError> {
        Ok(RemoteExitStatus {
            code,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    pub(crate) fn transport_err() -> Result<RemoteExitStatus, RemoteShellError> {
        Err(RemoteShellError::Transport {
            message: "ssh: connect to host 203.0.113.7 port 22: Connection timed out".to_owned(),
        })
    }

    /// Scripted shell: records every argv (space-joined, prefixed `shell:`)
    /// into the shared event log and answers via the responder.
    pub(crate) struct ScriptedShell {
        pub(crate) log: EventLog,
        pub(crate) responder: Arc<Responder>,
    }

    impl RemoteShellHost for ScriptedShell {
        fn read_file(&self, _p: &str) -> Result<Vec<u8>, RemoteShellError> {
            unimplemented!()
        }
        fn write_file(&self, _p: &str, _b: &[u8], _m: u16) -> Result<(), RemoteShellError> {
            unimplemented!()
        }
        fn stat(&self, _p: &str) -> Result<RemoteStat, RemoteShellError> {
            unimplemented!()
        }
        fn run_argv(
            &self,
            argv: &[&str],
            _env: &[(&str, &str)],
            _stdin: &[u8],
        ) -> Result<RemoteExitStatus, RemoteShellError> {
            let owned: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
            self.log
                .lock()
                .expect("event log")
                .push(format!("shell:{}", owned.join(" ")));
            (self.responder)(&owned)
        }
        fn tcp_send_recv(
            &self,
            _a: &str,
            _p: &[u8],
            _t: Duration,
        ) -> Result<Vec<u8>, RemoteShellError> {
            unimplemented!()
        }
    }

    pub(crate) struct ShellAdapter {
        pub(crate) alias: String,
        pub(crate) log: EventLog,
        pub(crate) responder: Arc<Responder>,
        pub(crate) enforce_result: Result<(), String>,
        pub(crate) cleanup_result: Result<(), String>,
    }

    impl std::fmt::Debug for ShellAdapter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShellAdapter")
                .field("alias", &self.alias)
                .finish()
        }
    }

    impl ShellAdapter {
        pub(crate) fn new(alias: &str, log: &EventLog, responder: Arc<Responder>) -> Self {
            Self {
                alias: alias.to_owned(),
                log: Arc::clone(log),
                responder,
                enforce_result: Ok(()),
                cleanup_result: Ok(()),
            }
        }
    }

    impl NodeAdapter for ShellAdapter {
        fn platform(&self) -> VmGuestPlatform {
            VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            &self.alias
        }
        fn shell_host(&self) -> Result<Arc<dyn RemoteShellHost>, AdapterError> {
            Ok(Arc::new(ScriptedShell {
                log: Arc::clone(&self.log),
                responder: Arc::clone(&self.responder),
            }))
        }
        fn enforce_runtime(&self, _ctx: &OrchestrationContext) -> Result<(), AdapterError> {
            self.log
                .lock()
                .expect("event log")
                .push(format!("enforce:{}", self.alias));
            self.enforce_result
                .clone()
                .map_err(|message| AdapterError::Protocol { message })
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            self.log
                .lock()
                .expect("event log")
                .push(format!("cleanup:{}", self.alias));
            self.cleanup_result
                .clone()
                .map_err(|message| AdapterError::Protocol { message })
        }
        fn assert_node_clean(&self) -> Result<(), AdapterError> {
            Ok(())
        }
        fn install_daemon(
            &self,
            _s: &SourceArchive,
            _c: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _o: &MembershipOwnerKey,
            _p: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(&self, _k: BundleKind, _p: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(&self, _k: BundleKind, _p: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _k: BundleKind,
            _e: &str,
            _d: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _o: DaemonProbeOp,
            _e: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _p: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _d: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            Ok(())
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn collect_artifacts(&self, _d: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    /// Build a context over `nodes`, each with its own adapter.
    pub(crate) fn ctx_with_adapters(
        report_dir: &Path,
        adapters: Vec<ShellAdapter>,
    ) -> OrchestrationContext {
        let assignments = adapters
            .iter()
            .map(|a| NodeRoleAssignment {
                alias: a.alias.clone(),
                role: NodeRole::Client,
            })
            .collect();
        let mut map: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
        for adapter in adapters {
            map.insert(adapter.alias.clone(), Box::new(adapter));
        }
        OrchestrationContext {
            assignments,
            adapters: map,
            source_archive: None,
            report_dir: report_dir.to_path_buf(),
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
            relay_forward_candidate_endpoint: None,
        }
    }

    /// Unique scratch dir per test.
    pub(crate) fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cloud_node_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{ok, rc, scratch_dir, transport_err};
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellError};
    use std::sync::{Arc, Mutex};

    use super::test_support::{ScriptedShell, ShellAdapter, ctx_with_adapters};

    fn shell_with(
        responder: impl Fn(&[String]) -> Result<RemoteExitStatus, RemoteShellError>
        + Send
        + Sync
        + 'static,
    ) -> (ScriptedShell, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        (
            ScriptedShell {
                log: Arc::clone(&log),
                responder: Arc::new(responder),
            },
            log,
        )
    }

    fn render(shell: &ScriptedShell) -> String {
        render_node_diagnostics(
            shell,
            "azure-vm-1",
            "post-enforce",
            &Scrubber::with_needles(&[]),
            true,
        )
    }

    /// The command list is the contract: every command is bounded by a remote
    /// `timeout`, none can print key material, and the required surfaces are
    /// all present. Mutation caught: adding `dump` to `wg show`, dropping a
    /// timeout prefix, dropping a required command.
    #[test]
    fn command_list_is_bounded_and_carries_no_secret_commands() {
        for cmd in DIAG_COMMANDS {
            assert_eq!(cmd.argv[0], "timeout", "{} must be bounded", cmd.label);
            let secs: u32 = cmd.argv[1].parse().expect("timeout seconds");
            assert!((1..=30).contains(&secs), "{}: {secs}s", cmd.label);
            for arg in cmd.argv {
                assert_ne!(
                    *arg, "dump",
                    "{} must not use `dump` (private keys)",
                    cmd.label
                );
                assert!(
                    !arg.contains("private") && !arg.contains("psk") && !arg.contains("keys"),
                    "{}: suspicious arg {arg}",
                    cmd.label
                );
            }
        }
        let joined: Vec<String> = DIAG_COMMANDS.iter().map(|c| c.argv.join(" ")).collect();
        for required in [
            "nft list ruleset",
            "ip rule show",
            "ip route show table all",
            "wg show all",
            "ip neigh show",
            "conntrack -S",
            "conntrack -L",
            "tailscale status --json",
            "journalctl -u rustynetd -u tailscaled",
            "tcpdump -ni any -c 40",
        ] {
            assert!(
                joined.iter().any(|j| j.contains(required)),
                "missing diagnostic command: {required}"
            );
        }
        // wg is exactly `wg show all` (no trailing subcommand such as `dump`).
        assert!(joined.iter().any(|j| j.ends_with("wg show all")));
        let tcpdump = DIAG_COMMANDS
            .iter()
            .find(|c| c.argv.contains(&"tcpdump"))
            .expect("tcpdump entry");
        assert_eq!(tcpdump.argv[1], "6", "tcpdump window is 6 seconds");
    }

    /// Every failing command is recorded as a `capture error:` line naming the
    /// command, and capture continues past it. Mutation caught: swallowing the
    /// error or aborting the loop on a non-zero exit.
    #[test]
    fn failing_commands_are_recorded_and_capture_continues() {
        let (shell, log) = shell_with(|argv| {
            if argv.iter().any(|a| a == "conntrack") {
                rc(127, "sudo: conntrack: command not found")
            } else if argv.iter().any(|a| a == "tcpdump") {
                rc(124, "")
            } else if argv.iter().any(|a| a == "nft") {
                ok("table inet rustynet_boot {}\n")
            } else {
                ok("x\n")
            }
        });
        let out = render(&shell);
        assert!(out.contains("capture error: conntrack -S: rc=127"), "{out}");
        assert!(out.contains("(tool not installed?)"), "{out}");
        assert!(out.contains("table inet rustynet_boot {}"), "{out}");
        // tcpdump timing out at the window end is expected, not an error.
        assert!(
            !out.contains("capture error: tcpdump"),
            "tcpdump window end must not be an error: {out}"
        );
        assert!(out.contains("note: capture window ended"), "{out}");
        // All ten commands still ran after the conntrack failures.
        assert_eq!(log.lock().unwrap().len(), DIAG_COMMANDS.len() + 1, "{out}");
    }

    /// A timeout on a non-window command IS an error line.
    #[test]
    fn timeout_on_a_bounded_command_is_a_capture_error() {
        let (shell, _) = shell_with(|argv| {
            if argv.iter().any(|a| a == "nft") {
                rc(124, "")
            } else {
                ok("x\n")
            }
        });
        assert!(
            render(&shell).contains("capture error: nft list ruleset: timed out"),
            "timeout must be recorded"
        );
    }

    /// SSH unreachable: one explicit line, and the ten commands are not each
    /// retried against a dead transport.
    #[test]
    fn unreachable_ssh_emits_explicit_line_and_stops() {
        let (shell, log) = shell_with(|_| transport_err());
        let out = render(&shell);
        assert!(out.contains("capture error: ssh unreachable"), "{out}");
        assert_eq!(log.lock().unwrap().len(), 1, "only the probe may run");
    }

    /// A transport failure mid-capture is recorded and stops the rest.
    #[test]
    fn mid_capture_transport_failure_is_recorded_and_stops() {
        let (shell, log) = shell_with(|argv| {
            if argv.iter().any(|a| a == "wg") {
                transport_err()
            } else {
                ok("x\n")
            }
        });
        let out = render(&shell);
        assert!(out.contains("capture error: wg show all:"), "{out}");
        assert!(
            out.contains("remaining commands skipped after transport failure"),
            "{out}"
        );
        assert!(log.lock().unwrap().len() < DIAG_COMMANDS.len() + 1);
    }

    /// Key material never reaches the file: secret-bearing lines are dropped
    /// and tailscale JSON keys are never echoed. Mutation caught: removing the
    /// secret-line filter / echoing the raw tailscale JSON.
    #[test]
    fn key_material_is_not_written() {
        let ts = r#"{"BackendState":"Running","Self":{"Online":true,"Relay":"fra","PublicKey":"nodekey:TAILSCALEKEYMATERIAL"},
            "Peer":{"nodekey:abc":{"HostName":"katana","Online":true,"Active":true,"Relay":"fra","CurAddr":"198.51.100.9:41641","PublicKey":"nodekey:PEERKEYMATERIAL"}}}"#;
        let (shell, _) = shell_with(move |argv| {
            if argv.iter().any(|a| a == "wg") {
                ok(
                    "interface: rustynet0\n  private key: SECRETPRIVATEKEYBASE64=\n  public key: pub=\n  preshared key: PSKVALUE=\n  listening port: 51820\n",
                )
            } else if argv.iter().any(|a| a == "tailscale") {
                ok(ts)
            } else {
                ok("")
            }
        });
        let out = render(&shell);
        assert!(!out.contains("SECRETPRIVATEKEYBASE64"), "{out}");
        assert!(!out.contains("PSKVALUE"), "{out}");
        assert!(!out.contains("KEYMATERIAL"), "{out}");
        assert!(out.contains("listening port: 51820"), "{out}");
        assert!(
            out.contains("peer host=katana online=true active=true relay=fra path=direct"),
            "{out}"
        );
    }

    /// The node's public dataplane address is replaced wherever it appears,
    /// including in transport error text. Mutation caught: dropping the scrub.
    #[test]
    fn dataplane_address_is_scrubbed_from_output_and_errors() {
        let (shell, _) = shell_with(|argv| {
            if argv.iter().any(|a| a == "nft") {
                ok("ip daddr 203.0.113.7 udp dport 51820 accept\nip saddr 198.51.100.77 drop\n")
            } else if argv.iter().any(|a| a == "wg") {
                transport_err()
            } else {
                ok("")
            }
        });
        let out = render_node_diagnostics(
            &shell,
            "azure-vm-1",
            "post-enforce",
            &Scrubber::with_needles(&["203.0.113.7"]),
            true,
        );
        assert!(!out.contains("203.0.113.7"), "{out}");
        assert!(out.contains(DATAPLANE_PLACEHOLDER), "{out}");
        // A global address that is in NO scrub set is still caught by the
        // generic pass.
        assert!(!out.contains("198.51.100.77"), "{out}");
        assert!(out.contains(PUBLIC_IP_PLACEHOLDER), "{out}");
    }

    #[test]
    fn conntrack_filter_keeps_only_relevant_ports() {
        let raw = "udp 17 29 src=10.0.0.4 dst=198.51.100.9 sport=41641 dport=41641 [UNREPLIED]\n\
                   tcp 6 100 src=10.0.0.4 dst=1.2.3.4 sport=5555 dport=22 ESTABLISHED\n\
                   tcp 6 100 src=10.0.0.4 dst=1.2.3.4 sport=5556 dport=443 ESTABLISHED\n";
        let lines = post_process(PostProcess::ConntrackPortFilter, raw).unwrap();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines.iter().all(|l| !l.contains("dport=22")));
    }

    #[test]
    fn tailscale_summary_reports_direct_or_relay_without_addresses() {
        let ts = r#"{"BackendState":"Running","Peer":{"k":{"HostName":"katana","Online":true,"Relay":"fra","CurAddr":""}}}"#;
        let lines = summarize_tailscale_status(ts).unwrap();
        assert!(lines.iter().any(|l| l.contains("path=relay")), "{lines:?}");
        let direct = r#"{"Peer":{"k":{"HostName":"katana","Online":true,"Relay":"fra","CurAddr":"198.51.100.9:41641"}}}"#;
        let lines = summarize_tailscale_status(direct).unwrap();
        assert!(lines.iter().any(|l| l.contains("path=direct")), "{lines:?}");
        assert!(
            lines.iter().all(|l| !l.contains("198.51.100.9")),
            "the peer endpoint must not be kept: {lines:?}"
        );
        assert!(summarize_tailscale_status("not json").is_err());
    }

    /// End-to-end through the adapter seam: the file lands under logs/ with the
    /// `diag_<phase>_<alias>.txt` name and a hostile alias cannot escape.
    #[test]
    fn capture_writes_named_file_and_refuses_unsafe_names() {
        let dir = scratch_dir("diag_file");
        let log = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<super::test_support::Responder> = Arc::new(|_| ok("x\n"));
        let ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("node-a", &log, responder)]);
        capture_node_diagnostics(&ctx, "node-a", PHASE_POST_ENFORCE);
        let body = std::fs::read_to_string(dir.join("logs/diag_post-enforce_node-a.txt"))
            .expect("diag file");
        assert!(body.contains("== nft list ruleset =="), "{body}");

        capture_node_diagnostics(&ctx, "../escape", PHASE_POST_ENFORCE);
        capture_node_diagnostics(&ctx, "node-a", "../../x");
        assert!(!dir.join("escape").exists());
        let names: Vec<_> = std::fs::read_dir(dir.join("logs"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node with no adapter still gets a file recording why — never silence.
    #[test]
    fn missing_adapter_is_recorded_not_skipped() {
        let dir = scratch_dir("diag_noadapter");
        let mut ctx = ctx_with_adapters(&dir, vec![]);
        ctx.assignments.push(
            crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment {
                alias: "ghost".to_owned(),
                role: crate::vm_lab::orchestrator::role::NodeRole::Client,
            },
        );
        capture_all_nodes_diagnostics(&ctx, PHASE_MESH_STATUS_FAILURE);
        let body = std::fs::read_to_string(dir.join("logs/diag_mesh-status-failure_ghost.txt"))
            .expect("diag file");
        assert!(
            body.contains("capture error: no adapter for node"),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Generic scrub: global IP literals go, everything that explains routing
    /// (private, CGNAT/tailnet, loopback, link-local, ULA, masks) stays.
    /// Mutation caught: dropping the generic pass or over-scrubbing private
    /// ranges.
    #[test]
    fn global_ip_literals_are_scrubbed_and_local_ones_kept() {
        let text = "a 203.0.113.7:41641 b 198.51.100.9/32 c 2001:db8::7 d [2001:db8::8]:443 \
                    e 10.0.0.4 f 172.16.3.1 g 192.168.50.2 h 100.64.9.9 i 127.0.0.1 \
                    j 169.254.1.1 k fe80::1 l fd7a:115c:a1e0::5 m fc00::9 n 255.255.255.0 \
                    o 52:54:00:12:34:56 p 6.1.0-26 q 1.2.3.4.5 r ::1";
        let out = scrub_global_ip_literals(text);
        for gone in ["203.0.113.7", "198.51.100.9", "2001:db8::7", "2001:db8::8"] {
            assert!(!out.contains(gone), "{gone} survived: {out}");
        }
        assert!(out.contains("<public-ip>:41641"), "{out}");
        assert!(out.contains("<public-ip>/32"), "{out}");
        assert!(out.contains("[<public-ip>]:443"), "{out}");
        for kept in [
            "10.0.0.4",
            "172.16.3.1",
            "192.168.50.2",
            "100.64.9.9",
            "127.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "fd7a:115c:a1e0::5",
            "fc00::9",
            "255.255.255.0",
            "52:54:00:12:34:56",
            "6.1.0-26",
            "1.2.3.4.5",
            "::1",
        ] {
            assert!(out.contains(kept), "{kept} was wrongly scrubbed: {out}");
        }
    }

    /// The orchestrator's ssh_allow_cidrs single host is scrubbed even though
    /// a tailnet address is not "global". Mutation caught: dropping the
    /// mgmt-peer needles.
    #[test]
    fn ssh_allow_single_hosts_become_needles() {
        let scrub = Scrubber::new(Vec::new(), vec!["100.64.9.9".to_owned()], None, Vec::new());
        let out = scrub.scrub("peer 100.64.9.9 direct, guest 100.64.9.10");
        assert!(out.contains(MGMT_PEER_PLACEHOLDER), "{out}");
        assert!(!out.contains("100.64.9.9 "), "{out}");
        assert_eq!(
            single_host_cidrs("100.64.9.9/32, 192.168.0.0/24,fd7a::9/128,10.0.0.1/31"),
            vec![
                "100.64.9.9".parse::<std::net::IpAddr>().unwrap(),
                "fd7a::9".parse::<std::net::IpAddr>().unwrap()
            ]
        );
    }

    /// The overlay redaction set (as the ledger writers build it) really
    /// reaches the diagnostics scrub. Mutation caught: ignoring the overlay.
    #[test]
    fn overlay_redaction_needles_are_scrubbed() {
        let dir = scratch_dir("overlay");
        let overlay_file = dir.join("overlay.json");
        std::fs::write(
            &overlay_file,
            r#"{"entries":[{"alias":"cloud-1","ssh_target":"ubuntu@cloud-secret-host.example"}]}"#,
        )
        .unwrap();
        let overlay = crate::vm_lab::overlay_redaction_from_file(&overlay_file).unwrap();
        let scrub = Scrubber::new(Vec::new(), Vec::new(), Some(overlay), Vec::new());
        let out = scrub.scrub("ssh: connect to host cloud-secret-host.example port 22: timed out");
        assert!(!out.contains("cloud-secret-host.example"), "{out}");
        assert!(out.contains("local-overlay"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broadened_secret_filter_drops_token_like_lines() {
        for line in [
            "  private key: x",
            "preshared key: x",
            "Authkey=abc",
            "tskey-auth-k123",
            "passphrase file set",
            "Bearer TOKEN abc",
            "client_secret=foo",
        ] {
            assert!(is_secret_line(line), "{line}");
        }
        assert!(!is_secret_line("listening port: 51820"));
    }

    /// Files are created mode 0600 and a looser pre-existing file is narrowed.
    #[cfg(unix)]
    #[test]
    fn diagnostics_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("diag_mode");
        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let pre = logs.join("diag_post-enforce_node-a.txt");
        std::fs::write(&pre, "old").unwrap();
        std::fs::set_permissions(&pre, std::fs::Permissions::from_mode(0o644)).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<super::test_support::Responder> = Arc::new(|_| ok("x\n"));
        let ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("node-a", &log, responder)]);
        capture_node_diagnostics(&ctx, "node-a", PHASE_POST_ENFORCE);
        capture_node_diagnostics(&ctx, "node-a", PHASE_TRAFFIC_MATRIX_FAILURE);
        for name in [
            "diag_post-enforce_node-a.txt",
            "diag_traffic-matrix-failure_node-a.txt",
        ] {
            let mode = std::fs::metadata(logs.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The 6 s capture window runs for failure phases and dataplane-addressed
    /// nodes, not for an ordinary post-enforce snapshot. Mutation caught:
    /// always/never including the window.
    #[test]
    fn capture_window_only_for_failure_phases_or_dataplane_nodes() {
        let run = |phase: &str, dataplane: bool| -> Vec<String> {
            let dir = scratch_dir("diag_window");
            let log: super::test_support::EventLog = Arc::new(Mutex::new(Vec::new()));
            let responder: Arc<super::test_support::Responder> = Arc::new(|_| ok("x\n"));
            let mut ctx =
                ctx_with_adapters(&dir, vec![ShellAdapter::new("node-a", &log, responder)]);
            if dataplane {
                let inv = dir.join("inv.json");
                std::fs::write(
                    &inv,
                    r#"{"version":1,"entries":[{"alias":"node-a","ssh_target":"100.64.15.9","dataplane_endpoint":"203.0.113.7","platform":"linux"}]}"#,
                )
                .unwrap();
                ctx.inventory_path = Some(inv);
            }
            capture_node_diagnostics(&ctx, "node-a", phase);
            let events = log.lock().unwrap().clone();
            let _ = std::fs::remove_dir_all(&dir);
            events
        };
        let has_tcpdump = |e: &Vec<String>| e.iter().any(|l| l.contains("tcpdump"));
        assert!(!has_tcpdump(&run(PHASE_POST_ENFORCE, false)));
        assert!(has_tcpdump(&run(PHASE_POST_ENFORCE, true)));
        assert!(has_tcpdump(&run(PHASE_MESH_STATUS_FAILURE, false)));
        assert!(has_tcpdump(&run(PHASE_TRAFFIC_MATRIX_FAILURE, false)));
    }
}
