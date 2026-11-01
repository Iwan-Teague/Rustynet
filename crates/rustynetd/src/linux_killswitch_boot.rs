#![allow(clippy::result_large_err)]

//! L8 — Linux boot-time killswitch verifier **and pre-protective installer**.
//!
//! ## Verifier (original L8 shape)
//!
//! At boot the daemon programs an `inet` family table holding the
//! `killswitch` and `forward` chains via `phase10::LiveSystem`. The
//! L8 audit shape is: between cold-boot and the first daemon start,
//! and again across any unit restart, there is a window where the
//! killswitch table is absent and the host can leak traffic to the
//! underlay. The mitigation tracked by this slice is a dedicated
//! verifier the systemd unit can invoke as `ExecStartPre` (and that
//! a future boot-time service can invoke before `network-online.target`)
//! to refuse to bring the `WireGuard` interface up unless the
//! killswitch is already in place.
//!
//! ## Boot-time pre-protective installer
//!
//! When `--install-boot-killswitch` is passed to the CLI, the module
//! also installs a minimal `inet rustynet_boot` table **before** the
//! daemon starts.  This table survives daemon teardown because
//! `disconnect-cleanup` only removes the daemon's generation-rotated
//! `rustynet_g<N>` tables; `rustynet_boot` is left intact until the
//! next ExecStartPre reinstalls it in place (idempotent `add` +
//! flush-under-policy-drop, so the filter window is never opened) or a
//! manual `nft delete table inet rustynet_boot` removes it.
//!
//! The purpose is to provide an SSH recovery path when the daemon fails
//! to start or is in fail-closed mode.  If `RUSTYNET_FAIL_CLOSED_SSH_ALLOW`
//! is true in the service environment, the boot table includes per-CIDR
//! TCP-port-22 accept rules so an operator can always reach the node via
//! SSH even after the daemon's killswitch is cleaned up.
//!
//! ### Interaction with the daemon's killswitch
//!
//! The boot table (`rustynet_boot`) and the daemon's table (`rustynet_g<N>`)
//! both hook into `output` at priority 0.  In nftables, an `accept` verdict
//! in one base chain does **not** terminate traversal of other base chains at
//! the same hook — a `policy drop` in the daemon's chain still drops the
//! packet.  The boot table's SSH accept rules therefore only take effect when
//! the daemon's table has been removed (after `disconnect-cleanup` or graceful
//! shutdown).  While the daemon is actively running in fail-closed mode with
//! `RUSTYNET_FAIL_CLOSED_SSH_ALLOW=false`, SSH remains blocked; to unblock
//! SSH during the daemon's lifetime set `RUSTYNET_FAIL_CLOSED_SSH_ALLOW=true`
//! in `/etc/default/rustynetd`.
//!
//! This module owns the pure evaluator + typed report shape + boot installer.
//! The collector parses `nft list ruleset` output and the
//! `/sys/class/net/<iface>` directory presence; both surfaces are
//! deterministic on Linux and trivially mockable in tests.
//!
//! Wired through the CLI as `rustynetd linux-killswitch-boot-check`.
//! Off-Linux the collector emits a clear blocker; the check is only
//! meaningful on a Linux runtime host.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Reviewed Linux killswitch table name. The runtime programs the
/// killswitch under a generation-rotated form `inet rustynet_g<N>`
/// (see `phase10::LiveSystem::firewall_table_name`) so it can swap
/// between generations atomically without opening a leak window. The
/// verifier accepts that rotated form as well as the canonical bare
/// `inet rustynet` — see `line_is_reviewed_table_header` for the
/// matcher. This constant remains the canonical name reported in
/// drift messages so operators see a stable identifier regardless of
/// which generation slot is currently live.
pub const REVIEWED_KILLSWITCH_TABLE: &str = "rustynet";

/// Reviewed Linux killswitch family (nftables `inet` family covers
/// both IPv4 and IPv6 in one programmed chain set).
pub const REVIEWED_KILLSWITCH_FAMILY: &str = "inet";

/// Required chains inside the reviewed killswitch table. A missing
/// chain is a hard fail-closed reason.
pub const REVIEWED_REQUIRED_CHAINS: &[&str] = &["killswitch", "forward"];

/// Required rule shapes inside the `killswitch` chain. Each shape is
/// the substring fragment the live ruleset must contain on a single
/// line; the verifier does a substring match, not a full nftables
/// parse, so the matcher is robust against cosmetic whitespace
/// drift.
pub const REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS: &[&str] = &[
    // Allow loopback so the daemon's local IPC and resolver still
    // work even when the killswitch is otherwise closed.
    "oifname \"lo\" accept",
    // Established/related must always pass — without it, return
    // traffic for handshakes is dropped and the killswitch becomes
    // a black hole even for legitimate traffic. AQ-70/F2: the pass
    // is THREE family- and port-scoped rules, so an established
    // plaintext-DNS (53), DoT (tcp/853) or DoQ (udp/853) flow can
    // never ride the established accept past the DNS drops, and
    // established IPv6 cannot ride it in an IPv4-only posture.
    "ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept",
    "ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept",
    "ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept",
];

/// nftables table name for the boot-time pre-protective killswitch
/// installed by `linux-killswitch-boot-check --install-boot-killswitch`.
/// Distinct from the daemon's generation-rotated tables (`rustynet_g<N>`)
/// so it survives `disconnect-cleanup` and can coexist without confusing
/// the L8 verifier.
pub const BOOT_KILLSWITCH_TABLE: &str = "rustynet_boot";

/// A validated SSH management CIDR used when building boot-time
/// killswitch SSH-allow rules.  Owns the IP family string ("ip" for
/// IPv4, "ip6" for IPv6) and the CIDR string in `addr/prefix` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSshCidr {
    /// nftables address-family selector for this CIDR ("ip" or "ip6").
    pub family: &'static str,
    /// CIDR in `<addr>/<prefix>` form, e.g. "192.168.1.0/24".
    pub cidr: String,
}

impl BootSshCidr {
    /// Parse and validate a CIDR string.  Returns an error if the
    /// address or prefix are syntactically invalid.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty CIDR string".to_owned());
        }
        let (ip_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR missing '/': {s}"))?;
        let ip: std::net::IpAddr = ip_str
            .parse()
            .map_err(|e| format!("invalid IP address in CIDR {s}: {e}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix length in CIDR {s}: {e}"))?;
        let family: &'static str = match ip {
            std::net::IpAddr::V4(_) => {
                if prefix > 32 {
                    return Err(format!("IPv4 prefix length > 32 in CIDR {s}"));
                }
                "ip"
            }
            std::net::IpAddr::V6(_) => {
                if prefix > 128 {
                    return Err(format!("IPv6 prefix length > 128 in CIDR {s}"));
                }
                "ip6"
            }
        };
        // QH-60: the boot check and the daemon consume the SAME env value,
        // but this parser used to accept shapes the daemon's ManagementCidr
        // refuses — including 0.0.0.0/0. That split-brain installed an
        // unrestricted port-22 boot rule and THEN the daemon exited
        // InvalidConfig, leaving the broad rule live. Funnel through the
        // same bounded-operator-range validator so the two parsers cannot
        // drift apart.
        crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr(s)
            .map_err(|err| format!("boot ssh allow CIDR rejected: {err}"))?;
        Ok(Self {
            family,
            cidr: s.to_owned(),
        })
    }
}

/// A validated traversal-bootstrap endpoint (a STUN server) used when
/// building boot-time killswitch allow rules.  Owns the IP family
/// string ("ip" for IPv4, "ip6" for IPv6), the bare address, and the
/// UDP port, so the emitted rule matches exactly one destination
/// socket rather than opening a port range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootTraversalEndpoint {
    /// nftables address-family selector for this endpoint ("ip" or "ip6").
    pub family: &'static str,
    /// Bare destination address, e.g. "74.125.250.129".
    pub addr: String,
    /// Destination UDP port, e.g. 19302.
    pub port: u16,
}

impl BootTraversalEndpoint {
    /// Parse and validate an `ip:port` endpoint string.  IPv6 endpoints
    /// use the bracketed `[addr]:port` form, matching the daemon's own
    /// `--traversal-stun-servers` parser.  Returns an error rather than
    /// silently skipping a malformed entry: a STUN server that fails to
    /// parse must fail the boot install loudly, not leave the operator
    /// believing traversal egress is permitted when it is not.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty traversal endpoint string".to_owned());
        }
        let addr: std::net::SocketAddr = s
            .parse()
            .map_err(|e| format!("invalid traversal endpoint {s}: {e}"))?;
        if addr.port() == 0 {
            return Err(format!("traversal endpoint port must not be 0: {s}"));
        }
        let family: &'static str = match addr {
            std::net::SocketAddr::V4(_) => "ip",
            std::net::SocketAddr::V6(_) => "ip6",
        };
        Ok(Self {
            family,
            addr: addr.ip().to_string(),
            port: addr.port(),
        })
    }
}

/// Install a minimal pre-protective boot-time killswitch table
/// (`inet rustynet_boot`) before the daemon starts.  The install is
/// in-place and idempotent: the table and base chain are re-asserted
/// with `add` (never deleted), the chain is flushed while its
/// `policy drop` is already in force, and only then are the accept
/// rules re-added.  At no point is an ExecStartPre call left without
/// an output filter (fail closed).
///
/// The table installs:
/// - loopback accept
/// - three scoped `ct state established,related ... accept` rules
///   (AQ-70/F2: SSH reply traffic still passes; established DNS/DoT/DoQ
///   and IPv4-only scoping can no longer shadow the DNS drops)
/// - outbound accept for the WireGuard interface (passthrough for
///   tunnel traffic when the daemon later brings the interface up)
/// - outbound UDP accept on `wg_listen_port` when `Some(port)` is
///   supplied — without this the daemon's traversal-probe initial
///   handshake datagrams are dropped by this boot chain even though
///   the daemon's own generation-rotated table would accept them.
///   Both chains hook `output` at priority 0 and a `policy drop`
///   verdict in this boot chain still drops the packet regardless of
///   what the daemon chain decides.
/// - outbound UDP accept for each configured traversal-bootstrap
///   endpoint (STUN server) in `traversal_endpoints` — same reasoning
///   as `wg_listen_port` above.  STUN candidate gathering leaves the
///   host on an ephemeral source port toward the server's port, so the
///   `wg_listen_port` rule does not cover it and the boot chain's
///   `policy drop` silently vetoes every STUN datagram the daemon's own
///   table accepts.  Without this the daemon can never gather a
///   server-reflexive candidate and NAT traversal cannot work at all.
/// - TCP port 22 accept for each CIDR in `ssh_cidrs` when
///   `ssh_allow` is true
/// - implicit `policy drop` for everything else
///
/// On non-Linux hosts this is a no-op (the killswitch is Linux-only).
///
/// The interface name is validated BEFORE any nft exec. This installer is
/// the one firewall-enforcement path that execs `nft` directly instead of
/// through the privileged helper's argv allowlist (whose `is_interface_name`
/// gate covers every runtime rule shape), and nft parses its concatenated
/// arguments as grammar — so an unvalidated name could add match terms or
/// verdicts to the boot chain. The value is operator-reachable from real
/// config: the reviewed systemd unit interpolates `${RUSTYNET_WG_INTERFACE}`
/// into `--iface` on the ExecStartPre line, which arrives here verbatim as a
/// single argument. The character class mirrors the runtime path's
/// `validate_net_device_name` exactly so boot and runtime cannot drift.
/// AQ-253: the established/related rule bodies the boot killswitch installs,
/// delegated to the runtime generator's ONE shared list
/// (`LinuxCommandSystem::established_related_accept_tokens`) so the boot-time
/// chain and the daemon's killswitch/forward chains cannot drift apart (the
/// bodies used to be re-spelled inline here — a byte-for-byte copy that only
/// a comment tied to the shared list). Cross-platform on purpose: the unit
/// test cross-pins this list, and the reviewed fragments rendered from it,
/// on every OS, while the nft exec that consumes it is Linux-only.
pub fn boot_established_related_rule_bodies() -> Vec<Vec<String>> {
    crate::phase10::LinuxCommandSystem::established_related_accept_tokens()
}

/// The interface-name gate shared by both boot installer entry points
/// (`install_linux_boot_killswitch` and
/// `install_linux_boot_killswitch_with_substrate_transit`). Runs BEFORE any
/// nft argv is built: see the full rationale on
/// `install_linux_boot_killswitch`.
fn validate_boot_iface_name(iface: &str) -> Result<(), String> {
    if iface.is_empty()
        || iface.len() > 15
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(format!(
            "invalid boot killswitch interface name {iface:?}: must be 1-15 chars of \
             [A-Za-z0-9_-] (mirrors the runtime dataplane's device-name gate)"
        ));
    }
    Ok(())
}

pub fn install_linux_boot_killswitch(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
    traversal_endpoints: &[BootTraversalEndpoint],
) -> Result<(), String> {
    validate_boot_iface_name(iface)?;
    install_linux_boot_killswitch_inner(
        iface,
        ssh_allow,
        ssh_cidrs,
        wg_listen_port,
        traversal_endpoints,
    )
}

/// The boot chain's rules as an ordered nft argv sequence, WITHOUT the
/// install prelude (the table add / policy-drop chain add / chain flush;
/// see `boot_killswitch_install_prelude`). Every rule body is
/// byte-identical to the
/// previous exec-as-you-build implementation; the ONLY reason this is a pure
/// builder now is that the substrate-transit install must splice the transit
/// rules into the MIDDLE of the sequence instead of appending them (see
/// `install_linux_boot_killswitch_with_substrate_transit`).
///
/// Cross-platform on purpose: the splice/order tests pin this sequence on
/// every OS, while the nft exec that consumes it is Linux-only. The Linux
/// consumers are cfg-gated, so off-Linux builds legitimately see no caller.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn boot_killswitch_rule_argvs(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
    traversal_endpoints: &[BootTraversalEndpoint],
) -> Vec<Vec<String>> {
    let mut rules: Vec<Vec<String>> = Vec::new();
    let mut add_rule = |body: Vec<String>| {
        let mut argv: Vec<String> = ["add", "rule", "inet", BOOT_KILLSWITCH_TABLE, "killswitch"]
            .iter()
            .map(|token| (*token).to_owned())
            .collect();
        argv.extend(body);
        rules.push(argv);
    };
    add_rule(vec![
        "oifname".to_owned(),
        "lo".to_owned(),
        "accept".to_owned(),
    ]);
    // AQ-70/F2: established/related passes through THREE scoped rules so an
    // established DNS/DoT/DoQ flow is never accepted ahead of the DNS drops
    // and established IPv6 stays on the policy-drop path. AQ-253: the bodies
    // ARE the runtime generator's `established_related_accept_tokens`
    // (`boot_established_related_rule_bodies`), so this boot chain cannot
    // drift from the daemon's killswitch/forward chains.
    for rule_tokens in boot_established_related_rule_bodies() {
        add_rule(rule_tokens);
    }
    // Allow outbound through the WireGuard interface.  The iface may not
    // exist yet at ExecStartPre time, but nftables accepts the rule and
    // will match it once the interface comes up.
    add_rule(vec![
        "oifname".to_owned(),
        iface.to_owned(),
        "accept".to_owned(),
    ]);
    // Allow outbound UDP to the WireGuard listen port so the daemon's
    // traversal-probe handshake datagrams can leave the host during the
    // window where this boot chain hooks `output` alongside the daemon's
    // generation-rotated chain.  Without this rule, every WG outbound
    // datagram returns EPERM regardless of the daemon's own ruleset,
    // because both chains share the `output` hook and `policy drop` in
    // either chain drops the packet.
    if let Some(port) = wg_listen_port {
        let port_str = port.to_string();
        add_rule(vec![
            "udp".to_owned(),
            "dport".to_owned(),
            port_str.clone(),
            "accept".to_owned(),
        ]);
        // Also match outbound WireGuard by SOURCE port.  The dport rule only
        // covers peers listening on our own port; a peer reached at its
        // server-reflexive candidate sits on an arbitrary NAT-mapped port, so
        // without this the handshake is dropped here and NAT traversal can
        // never complete.  Every datagram the daemon emits leaves its bound
        // WireGuard socket with this source port.
        add_rule(vec![
            "udp".to_owned(),
            "sport".to_owned(),
            port_str,
            "accept".to_owned(),
        ]);
    }
    // Allow outbound UDP to each configured traversal-bootstrap endpoint.
    // STUN gathering uses an ephemeral source port toward the server's
    // destination port, so the `wg_listen_port` rule above does not match
    // it.  Both chains share the `output` hook, so without this rule the
    // boot chain's `policy drop` vetoes every STUN datagram even though the
    // daemon's generation-rotated table explicitly accepts it, and the
    // daemon can never gather a server-reflexive candidate.  The match is
    // narrowed to the exact destination address and port so this stays a
    // pinhole rather than a general UDP egress hole.
    for endpoint in traversal_endpoints {
        let port_str = endpoint.port.to_string();
        add_rule(vec![
            endpoint.family.to_owned(),
            "daddr".to_owned(),
            endpoint.addr.clone(),
            "udp".to_owned(),
            "dport".to_owned(),
            port_str,
            "accept".to_owned(),
        ]);
    }
    if ssh_allow {
        for cidr in ssh_cidrs {
            add_rule(vec![
                cidr.family.to_owned(),
                "daddr".to_owned(),
                cidr.cidr.clone(),
                "tcp".to_owned(),
                "dport".to_owned(),
                "22".to_owned(),
                "accept".to_owned(),
            ]);
        }
    }
    rules
}

/// The install prelude as an ordered nft argv sequence, BEFORE any rule:
/// [1] idempotent `add table` (creates the table if absent, no-op if
/// present), [2] idempotent `add chain` that re-asserts the output hook
/// with `policy drop` (an existing chain with different attributes makes
/// this step fail -> abort), [3] `flush chain` executed while the policy
/// drop is already in force, so the chain drops everything until the
/// accept rules are re-added.  The replacement is therefore fail closed:
/// there is no moment without an output filter, and the install path
/// never contains a `delete` step.
///
/// Cross-platform on purpose: the prelude tests pin this sequence on
/// every OS, while the nft exec that consumes it is Linux-only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn boot_killswitch_install_prelude() -> Vec<Vec<String>> {
    fn owned(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_owned()).collect()
    }
    vec![
        owned(&["add", "table", "inet", BOOT_KILLSWITCH_TABLE]),
        owned(&[
            "add",
            "chain",
            "inet",
            BOOT_KILLSWITCH_TABLE,
            "killswitch",
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            "0",
            ";",
            "policy",
            "drop",
            ";",
            "}",
        ]),
        owned(&[
            "flush",
            "chain",
            "inet",
            BOOT_KILLSWITCH_TABLE,
            "killswitch",
        ]),
    ]
}

/// The full ordered install sequence: prelude first, then the chain
/// rules.  Composing here (instead of interleaving) keeps a single
/// hardened path: rules can never run before the policy-drop chain is
/// in place, and the whole list is replayable by the injectable
/// executor below.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn boot_killswitch_full_install_argv_sequence(rule_argvs: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut full = boot_killswitch_install_prelude();
    full.extend(rule_argvs.iter().cloned());
    full
}

/// The destructive nft verbs the boot install guard refuses.  The delete
/// verb is spelled with `concat!` ON PURPOSE: the source-pin test forbids a
/// quoted `delete` literal anywhere in the impl (outside comments), and
/// this constant is a runtime COMPARISON token, not the construction of a
/// delete argv.  Runtime spelling is what the guard inspects, so a
/// split-string re-introduction produces the identical token and cannot
/// bypass it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NFT_DELETE_VERB: &str = concat!("del", "ete");
/// See `NFT_DELETE_VERB`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NFT_DESTROY_VERB: &str = "destroy";

/// Cross-platform runtime guard for the boot install path: decide whether
/// an nft argv uses a destructive verb that must never run during a boot
/// install.  The verb is the first token after an optional program token
/// (`nft` or a path ending in `/nft`) and any leading options.  Refused:
/// `delete`, `destroy`, and every `flush` target except `chain` (the
/// install only ever wants `flush chain`; `flush table` / `flush ruleset`
/// would widen the blast radius beyond the boot chain).  This backs the
/// source-pin literal grep with a RUNTIME token inspection, so a delete
/// re-introduced with a split source string cannot bypass it (pinned by
/// the `boot_install_guard_*` tests).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nft_argv_is_forbidden(argv: &[String]) -> bool {
    let mut idx = 0;
    if matches!(argv.first(), Some(t) if t == "nft" || t.ends_with("/nft")) {
        idx = 1;
    }
    while matches!(argv.get(idx), Some(t) if t.starts_with('-')) {
        idx += 1;
    }
    let verb = argv.get(idx).map(String::as_str);
    if verb == Some(NFT_DELETE_VERB) || verb == Some(NFT_DESTROY_VERB) {
        return true;
    }
    if verb == Some("flush") {
        return argv.get(idx + 1).map(String::as_str) != Some("chain");
    }
    false
}

/// Cross-platform executor for the full ordered boot install argv
/// sequence (prelude + rules): run every argv through the injectable
/// runner in order.  Before ANY runner invocation each argv passes the
/// runtime guard `nft_argv_is_forbidden`: a destructive verb aborts the
/// install with an error naming the offending argv, and the runner is
/// never invoked for it.  The first runner error then aborts the install
/// (fail closed): later steps are never attempted, so a half-installed
/// state always keeps at least the `policy drop` filter.  The runner
/// decides how argvs are executed (Linux spawns `nft` argv-only; tests
/// record or fail on demand).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_boot_killswitch_argv_sequence<F>(argvs: &[Vec<String>], mut runner: F) -> Result<(), String>
where
    F: FnMut(&[String]) -> Result<(), String>,
{
    for argv in argvs {
        if nft_argv_is_forbidden(argv) {
            return Err(format!(
                "boot install refused a destructive nft argv: {argv:?}"
            ));
        }
        runner(argv)?;
    }
    Ok(())
}

/// Cross-platform: does this argv target `add chain`?  That is the one
/// nft step whose failure usually means the existing boot chain has
/// different attributes than the ones the install re-asserts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_add_chain_argv(argv: &[String]) -> bool {
    argv.first().map(String::as_str) == Some("add")
        && argv.get(1).map(String::as_str) == Some("chain")
}

/// Cross-platform: the operator-facing remedy attached to an `add chain`
/// mismatch.  The installer never deletes anything itself; it names the
/// manual remedy verbatim (the source pin asserts this text stays).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn add_chain_mismatch_remedy(err: &str) -> String {
    format!(
        "{err}; the existing boot chain may have different attributes; \
         fix manually with `nft delete table inet rustynet_boot` and then \
         restart the unit (the installer itself never deletes the table)"
    )
}

/// Cross-platform: the executor's whole per-step error mapping — attach
/// the remedy ONLY to `add chain` failures and pass every other error
/// through verbatim.  Hoisted out of the cfg(linux) closure so both
/// polarities are unit-tested on every OS and the Linux body has no
/// condition of its own to rot (review R4/M11).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn map_boot_install_step_error(argv: &[String], err: String) -> String {
    if is_add_chain_argv(argv) {
        add_chain_mismatch_remedy(&err)
    } else {
        err
    }
}

/// Linux-only executor for the ordered boot argv sequence: re-assert the
/// boot table and base chain in place (idempotent `add`), flush the
/// chain while `policy drop` is in force, then exec each rule argv in
/// order. Any nft failure aborts the install (fail closed), exactly like
/// the previous exec-as-you-build path.
#[cfg(target_os = "linux")]
fn install_boot_killswitch_rule_sequence(rule_argvs: &[Vec<String>]) -> Result<(), String> {
    // Argv-only helper: no shell construction, args are separate tokens.
    fn nft(args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| format!("nft spawn failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nft {} failed ({}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    let full = boot_killswitch_full_install_argv_sequence(rule_argvs);
    run_boot_killswitch_argv_sequence(&full, |argv| {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        nft(&refs).map_err(|err| map_boot_install_step_error(argv, err))
    })
}

#[cfg(target_os = "linux")]
fn install_linux_boot_killswitch_inner(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
    traversal_endpoints: &[BootTraversalEndpoint],
) -> Result<(), String> {
    install_boot_killswitch_rule_sequence(&boot_killswitch_rule_argvs(
        iface,
        ssh_allow,
        ssh_cidrs,
        wg_listen_port,
        traversal_endpoints,
    ))
}

/// LAB-ONLY (AQ-256, review finding 1): the boot table's substrate transit
/// rules. `rustynet_boot` hooks `output` at the same priority as the daemon's
/// generation table and stays live for the daemon's whole lifetime, and an
/// accept in one base chain does not exempt a packet from another, so the
/// vxlan encapsulation must be allowed in BOTH tables (review experiments
/// D1/D2). The body is the ONE shared builder
/// (`lab_substrate_transit::substrate_transit_allow_tokens`) the runtime
/// emitter and the runtime assertion use; the boot table needs no WireGuard
/// change (its WireGuard allows are interface-agnostic, finding 13).
#[cfg(all(target_os = "linux", feature = "lab-substrate"))]
pub fn boot_substrate_transit_rule_argvs(
    transit: &crate::lab_substrate_transit::SubstrateTransit,
) -> Vec<Vec<String>> {
    transit
        .peers()
        .iter()
        .map(|peer| {
            let mut argv: Vec<String> =
                ["add", "rule", "inet", BOOT_KILLSWITCH_TABLE, "killswitch"]
                    .iter()
                    .map(|token| (*token).to_owned())
                    .collect();
            argv.extend(
                crate::lab_substrate_transit::substrate_transit_allow_tokens(
                    transit.underlay_interface(),
                    *peer,
                ),
            );
            argv
        })
        .collect()
}

/// LAB-ONLY (AQ-256): [`install_linux_boot_killswitch`] plus the substrate
/// transit rules when an attestation is active. Every refusal happens BEFORE
/// the first nft exec: the attestation was validated by the caller
/// (`lab_substrate_transit::load_for_boot_check`), and the WireGuard listen
/// port it needs is checked here first. With `None` this is exactly
/// [`install_linux_boot_killswitch`].
///
/// ## Rule order: transit rules precede the established/related accepts
///
/// The runtime emitter inserts the transit rules ABOVE the
/// established/related trio in the daemon's generation table (u42-r1
/// verified), so the transit counters see EVERY packet that matches the
/// rule shape. The boot installer used to APPEND them below the trio,
/// which made the boot-table transit counters see only the FIRST packet
/// of each NEW conntrack flow: the vxlan encapsulation collapses both
/// directions of a peer pair into ONE bidirectional conntrack flow whose
/// source-port hash (and therefore match) is fixed, and the persistent
/// WireGuard keepalive keeps that flow `established` forever, so on the
/// responder side of a pair the boot counter sits frozen at its
/// boot-time value (usually 0) no matter how much transit flows. That is
/// the u42-r1 `security_audit_validation` failure (boot-table counters
/// frozen on every host while the same rules rose in the generation
/// table).
///
/// Moving the transit rules above the trio is verdict-neutral — every
/// packet a transit rule accepts was previously accepted by the
/// established accept instead; only counter visibility changes, matching
/// the generation-table semantics. The splice point is directly after
/// the loopback accept so the boot chain keeps its canonical
/// lo-first shape.
#[cfg(all(target_os = "linux", feature = "lab-substrate"))]
pub fn install_linux_boot_killswitch_with_substrate_transit(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
    traversal_endpoints: &[BootTraversalEndpoint],
    substrate_transit: Option<&crate::lab_substrate_transit::SubstrateTransit>,
) -> Result<(), String> {
    // Refusal gate FIRST (before any nft exec): a transit install without
    // the real WireGuard listen port must exit with the boot table untouched.
    // The argv bodies themselves are computed in
    // `boot_killswitch_substrate_rule_argv_sequence` below.
    if substrate_transit.is_some() && wg_listen_port.unwrap_or(0) == 0 {
        return Err(crate::lab_substrate_transit::rejected(
            "linux-killswitch-boot-check was given no --wg-listen-port; the transit \
             needs the real WireGuard listen port",
        ));
    }
    validate_boot_iface_name(iface)?;
    let rule_argvs = boot_killswitch_substrate_rule_argv_sequence(
        iface,
        ssh_allow,
        ssh_cidrs,
        wg_listen_port,
        traversal_endpoints,
        substrate_transit,
    );
    install_boot_killswitch_rule_sequence(&rule_argvs)
}

/// The substrate boot install's full ordered rule sequence, WITHOUT the table
/// create/chain-add statements. Pure so the splice order (the fix for the
/// u42-r1 boot-counter freeze) is unit-testable without executing nft: the
/// transit argvs sit directly after the loopback accept, BEFORE the
/// established/related trio.
#[cfg(all(target_os = "linux", feature = "lab-substrate"))]
fn boot_killswitch_substrate_rule_argv_sequence(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
    traversal_endpoints: &[BootTraversalEndpoint],
    substrate_transit: Option<&crate::lab_substrate_transit::SubstrateTransit>,
) -> Vec<Vec<String>> {
    let transit_argvs = match substrate_transit {
        None => Vec::new(),
        Some(transit) => boot_substrate_transit_rule_argvs(transit),
    };
    let mut rule_argvs = boot_killswitch_rule_argvs(
        iface,
        ssh_allow,
        ssh_cidrs,
        wg_listen_port,
        traversal_endpoints,
    );
    if !transit_argvs.is_empty() {
        splice_argvs_after_loopback(&mut rule_argvs, transit_argvs);
    }
    rule_argvs
}

/// Insert `extra` argv sequences into `rules` directly after the loopback
/// accept rule (the boot chain's first rule), before everything else. Pure
/// and cross-platform so the splice position is unit-testable off-Linux. Its
/// Linux consumer is feature-gated, so other builds legitimately see no caller.
#[cfg_attr(
    not(all(target_os = "linux", feature = "lab-substrate")),
    allow(dead_code)
)]
fn splice_argvs_after_loopback(rules: &mut Vec<Vec<String>>, extra: Vec<Vec<String>>) {
    let is_loopback = |argv: &[String]| {
        argv.windows(2).any(|pair| {
            pair.first().map(String::as_str) == Some("oifname")
                && pair.get(1).map(String::as_str) == Some("lo")
        }) && argv.last().map(String::as_str) == Some("accept")
    };
    let at = rules
        .iter()
        .position(|argv| is_loopback(argv))
        .map(|index| index + 1)
        .unwrap_or(0);
    for (offset, argv) in extra.into_iter().enumerate() {
        rules.insert(at + offset, argv);
    }
}

#[cfg(not(target_os = "linux"))]
fn install_linux_boot_killswitch_inner(
    _iface: &str,
    _ssh_allow: bool,
    _ssh_cidrs: &[BootSshCidr],
    _wg_listen_port: Option<u16>,
    _traversal_endpoints: &[BootTraversalEndpoint],
) -> Result<(), String> {
    // Off-Linux: no-op. The boot-time killswitch is Linux-specific.
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKillswitchBootSnapshot {
    /// Absolute path of the nft ruleset capture used. Mostly for
    /// forensic forwarding into the report; the evaluator does not
    /// branch on the path.
    pub ruleset_source: String,
    /// True iff the verifier was able to actually inspect host state
    /// (Linux runtime host, nft binary present, `/sys/class/net`
    /// readable). False off-Linux or when the inspection couldn't
    /// run. The evaluator surfaces a clear blocker when this is
    /// false so the off-platform case doesn't claim `overall_ok`.
    #[serde(default = "default_host_observable_true")]
    pub host_observable: bool,
    /// True iff the reviewed family + table pair appears in the
    /// captured ruleset.
    pub table_present: bool,
    /// Chains the verifier found inside the reviewed table, in source
    /// order. Empty when `table_present` is false.
    pub chains_present: Vec<String>,
    /// Substring rule fragments the verifier found inside the
    /// `killswitch` chain. Empty when the chain is missing.
    pub killswitch_rule_fragments_present: Vec<String>,
    /// True iff the daemon's tunnel interface (e.g. `rustynet0`) is
    /// currently visible under `/sys/class/net/<iface>`. The L8
    /// invariant fails closed if the interface is up but the
    /// killswitch table is absent — that is the leak window.
    pub tunnel_interface_present: bool,
    /// The reviewed interface name the snapshot was captured against,
    /// passed through to the report for forensic context.
    pub tunnel_interface_name: String,
}

/// Default value for the `host_observable` field on old JSON that
/// predates the field — assume true so existing snapshots keep their
/// previous meaning. The off-Linux collector explicitly sets false.
fn default_host_observable_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKillswitchBootReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: LinuxKillswitchBootSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator. Walks the snapshot and aggregates every drift
/// reason in a single pass. Returns `Vec` (not `Result`) so the
/// caller decides how to handle the aggregate.
pub fn evaluate_linux_killswitch_boot_snapshot(
    snapshot: &LinuxKillswitchBootSnapshot,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();

    if !snapshot.host_observable {
        reasons.push(format!(
            "host state could not be observed via {}: \
             linux-killswitch-boot-check requires a Linux runtime host with \
             `nft` available and `/sys/class/net` readable",
            snapshot.ruleset_source
        ));
        return reasons;
    }

    // The boot-time invariant: if the tunnel interface is up, the
    // killswitch table MUST be in place. The reverse case (table
    // present, interface absent) is fine — that's the cold-boot
    // pre-up window the gate is designed to allow.
    if snapshot.tunnel_interface_present && !snapshot.table_present {
        let iface = &snapshot.tunnel_interface_name;
        reasons.push(format!(
            "tunnel interface {iface} is present in /sys/class/net but reviewed killswitch \
             table {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE} is missing — host \
             has a live tunnel without a programmed killswitch, traffic can leak to the \
             underlay"
        ));
    }

    if !snapshot.table_present {
        // No further per-chain checks are meaningful; the leak-window
        // reason above already captured the failing case.
        return reasons;
    }

    for required in REVIEWED_REQUIRED_CHAINS {
        if !snapshot.chains_present.iter().any(|c| c == required) {
            reasons.push(format!(
                "reviewed chain `{required}` missing from \
                 {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE}"
            ));
        }
    }

    if snapshot.chains_present.iter().any(|c| c == "killswitch") {
        for required in REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS {
            if !snapshot
                .killswitch_rule_fragments_present
                .iter()
                .any(|f| f == required)
            {
                reasons.push(format!(
                    "reviewed killswitch rule fragment {required:?} missing from \
                     {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE} killswitch chain"
                ));
            }
        }
    }

    reasons
}

pub fn build_linux_killswitch_boot_report(
    snapshot: LinuxKillswitchBootSnapshot,
) -> LinuxKillswitchBootReport {
    let drift_reasons = evaluate_linux_killswitch_boot_snapshot(&snapshot);
    let overall_ok = drift_reasons.is_empty();
    LinuxKillswitchBootReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Returns true iff `trimmed_line` opens a nftables table block for
/// the reviewed killswitch table — either the canonical bare form
/// `table inet rustynet {` or the generation-rotated form
/// `table inet rustynet_g<N> {` (one or more ASCII digits after `_g`).
/// Anything else, including unrelated tables that happen to start
/// with `rustynet` (e.g. `rustynet_nat_g1`), is rejected.
pub(crate) fn line_is_reviewed_table_header(trimmed_line: &str) -> bool {
    let prefix = format!("table {REVIEWED_KILLSWITCH_FAMILY} {REVIEWED_KILLSWITCH_TABLE}");
    let Some(after_name) = trimmed_line.strip_prefix(prefix.as_str()) else {
        return false;
    };
    if let Some(rest) = after_name.strip_prefix("_g") {
        // Generation-rotated form: require one or more digits, then `{`.
        let digit_count = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_count == 0 {
            return false;
        }
        return rest[digit_count..].trim_start().starts_with('{');
    }
    // Canonical bare form: name must end here — next non-whitespace is `{`.
    let next = after_name.chars().next();
    matches!(next, Some(' ') | Some('\t') | Some('{')) && after_name.trim_start().starts_with('{')
}

/// Parse `nft list ruleset` text and extract the chains found under
/// the reviewed killswitch table (`inet rustynet` or `inet
/// rustynet_g<N>`). Returns the table-present flag, the chain names
/// in source order, and any matched rule fragments from the
/// `killswitch` chain. Exposed (crate-visible) so tests can pin the
/// parser without shelling out to `nft`.
#[allow(dead_code)]
pub(crate) fn parse_nft_ruleset_for_killswitch(body: &str) -> (bool, Vec<String>, Vec<String>) {
    let mut in_table = false;
    let mut in_killswitch_chain = false;
    let mut brace_depth: i32 = 0;
    let mut chains: Vec<String> = Vec::new();
    let mut matched_fragments: Vec<String> = Vec::new();
    let mut table_present = false;

    for raw_line in body.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim_start();
        // Find the reviewed table header.
        if !in_table {
            if line_is_reviewed_table_header(trimmed) {
                in_table = true;
                table_present = true;
                brace_depth = 1;
            }
            continue;
        }
        // Track brace depth so we know when we leave the table.
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }
        // Look for `chain <name> {` declarations at depth 2 (one
        // inside the table, one inside the chain itself).
        if let Some(rest) = trimmed.strip_prefix("chain ") {
            // Extract the chain name (token up to space or `{`).
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() && !chains.contains(&name) {
                chains.push(name.clone());
            }
            in_killswitch_chain = name == "killswitch";
            continue;
        }
        // Inside the killswitch chain, look for any reviewed fragment.
        if in_killswitch_chain {
            for frag in REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS {
                if line.contains(frag) && !matched_fragments.iter().any(|m| m == frag) {
                    matched_fragments.push((*frag).to_owned());
                }
            }
        }
        // When we exit the table block, stop scanning.
        if brace_depth <= 0 {
            break;
        }
    }
    (table_present, chains, matched_fragments)
}

/// Cross-platform collector. On Linux runs `nft list ruleset` via
/// argv-exec (no shell), reads `/sys/class/net/<iface>`, and builds
/// the snapshot. Off-Linux every observable field is reported as
/// "could not observe; requires a Linux runtime host" via a
/// `table_present=false` + matching drift reason in the evaluator.
///
/// `iface_name` is the `WireGuard` tunnel interface the daemon will
/// bring up. If unknown to the caller, pass the reviewed default.
pub fn collect_linux_killswitch_boot_report(iface_name: &str) -> LinuxKillswitchBootReport {
    collect_linux_killswitch_boot_report_inner(iface_name)
}

#[cfg(target_os = "linux")]
fn collect_linux_killswitch_boot_report_inner(iface_name: &str) -> LinuxKillswitchBootReport {
    let tunnel_path = PathBuf::from(format!("/sys/class/net/{iface_name}"));
    let tunnel_interface_present = tunnel_path.exists();

    let ruleset_source = "nft list ruleset".to_string();
    let output = std::process::Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output();
    let body: String = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => String::new(),
    };

    let (table_present, chains_present, killswitch_rule_fragments_present) =
        parse_nft_ruleset_for_killswitch(body.as_str());

    let snapshot = LinuxKillswitchBootSnapshot {
        ruleset_source,
        host_observable: true,
        table_present,
        chains_present,
        killswitch_rule_fragments_present,
        tunnel_interface_present,
        tunnel_interface_name: iface_name.to_string(),
    };
    build_linux_killswitch_boot_report(snapshot)
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_killswitch_boot_report_inner(iface_name: &str) -> LinuxKillswitchBootReport {
    // Off-Linux: surface a clear blocker; the check is only
    // meaningful on a Linux runtime host. The evaluator sees
    // `host_observable=false` and emits the unobservable-host drift
    // reason — overall_ok stays false without us having to claim
    // anything about the killswitch state itself.
    let snapshot = LinuxKillswitchBootSnapshot {
        ruleset_source: "off-Linux host: nft not invoked".to_owned(),
        host_observable: false,
        table_present: false,
        chains_present: Vec::new(),
        killswitch_rule_fragments_present: Vec::new(),
        tunnel_interface_present: false,
        tunnel_interface_name: iface_name.to_owned(),
    };
    build_linux_killswitch_boot_report(snapshot)
}

#[cfg(test)]
mod tests {
    /// QH-60 drift pin: the boot parser must reject exactly the shapes the
    /// daemon's ManagementCidr rejects — the two consume the SAME env value,
    /// and their earlier drift let a 0.0.0.0/0 install an unrestricted
    /// port-22 boot rule while the daemon exited InvalidConfig.
    #[test]
    fn boot_ssh_cidr_rejects_what_management_cidr_rejects() {
        for banned in ["0.0.0.0/0", "::/0", "8.8.8.0/24"] {
            assert!(
                super::BootSshCidr::parse(banned).is_err(),
                "boot parser must reject {banned}"
            );
        }
        for allowed in ["192.168.64.0/24", "10.0.0.0/8", "fd00::/8", "100.64.0.0/10"] {
            assert!(
                super::BootSshCidr::parse(allowed).is_ok(),
                "boot parser must keep accepting {allowed}"
            );
        }
        // Source pin: the alignment must stay routed through the shared
        // validator, not a reimplementation that can drift again.
        let source = include_str!("linux_killswitch_boot.rs");
        let needle = format!("validate_mesh_egress_source_{}", "cidr");
        assert!(
            source.contains(needle.as_str()),
            "BootSshCidr::parse must call the shared containment validator"
        );
    }

    use super::*;

    fn ok_snapshot() -> LinuxKillswitchBootSnapshot {
        LinuxKillswitchBootSnapshot {
            ruleset_source: "test fixture".to_owned(),
            host_observable: true,
            table_present: true,
            chains_present: vec!["killswitch".to_owned(), "forward".to_owned()],
            killswitch_rule_fragments_present: REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_owned(),
        }
    }

    // ---- evaluator coverage -----------------------------------------------

    #[test]
    fn evaluator_rejects_unobservable_host() {
        let mut snap = ok_snapshot();
        snap.host_observable = false;
        snap.ruleset_source = "off-Linux host: nft not invoked".to_owned();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("host state could not be observed")),
            "unobservable-host reason must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_clean_snapshot() {
        let reasons = evaluate_linux_killswitch_boot_snapshot(&ok_snapshot());
        assert!(reasons.is_empty(), "clean snapshot must pass: {reasons:?}");
    }

    #[test]
    fn evaluator_accepts_pre_boot_window_with_no_interface_and_no_table() {
        // Cold boot: iface not up yet, killswitch not programmed yet.
        // This is the legitimate window the gate must allow.
        let mut snap = ok_snapshot();
        snap.tunnel_interface_present = false;
        snap.table_present = false;
        snap.chains_present.clear();
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons.is_empty(),
            "cold-boot pre-up window must pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_interface_up_but_killswitch_table_missing() {
        // The L8 leak shape: tunnel is up but the killswitch table is
        // gone. Could happen mid-restart if the daemon flushed the
        // table before shutdown and crashed before re-programming.
        let mut snap = ok_snapshot();
        snap.table_present = false;
        snap.chains_present.clear();
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("tunnel interface rustynet0 is present")
                    && r.contains("killswitch table")
                    && r.contains("missing")),
            "leak-window must be named: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_killswitch_chain() {
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["forward".to_owned()];
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("reviewed chain `killswitch` missing")),
            "missing killswitch chain must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_forward_chain() {
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["killswitch".to_owned()];
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("reviewed chain `forward` missing")),
            "missing forward chain must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_loopback_accept_rule_fragment() {
        let mut snap = ok_snapshot();
        snap.killswitch_rule_fragments_present
            .retain(|f| !f.contains("oifname \"lo\""));
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("oifname \\\"lo\\\" accept") && r.contains("missing")),
            "missing loopback fragment must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_established_related_fragment() {
        let mut snap = ok_snapshot();
        snap.killswitch_rule_fragments_present
            .retain(|f| !f.contains("established,related"));
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("ct state established,related") && r.contains("missing")),
            "missing est/rel fragment must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_does_not_check_rule_fragments_when_killswitch_chain_missing() {
        // If the killswitch chain isn't there, reporting "rule
        // fragments missing" would be noise — the chain-missing
        // reason already covers it.
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["forward".to_owned()];
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        // Exactly one drift reason: the chain-missing one. No noisy
        // per-fragment messages.
        let chain_missing = reasons
            .iter()
            .filter(|r| r.contains("reviewed chain `killswitch` missing"))
            .count();
        let fragment_missing = reasons
            .iter()
            .filter(|r| r.contains("rule fragment"))
            .count();
        assert_eq!(chain_missing, 1, "chain-missing must surface once");
        assert_eq!(
            fragment_missing, 0,
            "fragment-missing must stay quiet when chain absent: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_all_drift_reasons_in_one_pass() {
        // Construct the worst-case shape: table present but BOTH
        // chains missing, AND interface up but table missing flag NOT
        // set (because table_present=true means no leak-window
        // message). The evaluator must surface both chain-missing
        // reasons.
        let snap = LinuxKillswitchBootSnapshot {
            ruleset_source: "agg test".to_owned(),
            host_observable: true,
            table_present: true,
            chains_present: Vec::new(),
            killswitch_rule_fragments_present: Vec::new(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_owned(),
        };
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        let chain_count = reasons
            .iter()
            .filter(|r| r.contains("reviewed chain"))
            .count();
        assert_eq!(
            chain_count, 2,
            "both required chains must surface: {reasons:?}"
        );
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_snapshot() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxKillswitchBootReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        assert_eq!(
            report.schema_version, 1,
            "schema_version bump must be deliberate"
        );
    }

    // ---- nft ruleset parser coverage --------------------------------------

    #[test]
    fn parser_finds_table_and_both_chains_in_clean_ruleset() {
        let body = r#"
table inet rustynet {
        chain killswitch {
                type filter hook output priority 0; policy drop;
                oifname "lo" accept
                ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept
                oifname "rustynet0" accept
        }
        chain forward {
                type filter hook forward priority 0; policy drop;
                ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept
                iifname "rustynet0" oifname "eth0" accept
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present, "table must be detected");
        assert!(
            chains.iter().any(|c| c == "killswitch"),
            "killswitch chain must be detected: {chains:?}"
        );
        assert!(
            chains.iter().any(|c| c == "forward"),
            "forward chain must be detected: {chains:?}"
        );
        assert!(
            frags.iter().any(|f| f.contains("oifname \"lo\"")),
            "loopback fragment must match: {frags:?}"
        );
        assert!(
            frags.iter().any(|f| f.contains(
                "ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept"
            )),
            "scoped est/rel fragment must match: {frags:?}"
        );
    }

    #[test]
    fn parser_returns_table_absent_when_no_rustynet_table_present() {
        let body = r#"
table inet filter {
        chain input {
                type filter hook input priority 0; policy accept;
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(!present);
        assert!(chains.is_empty());
        assert!(frags.is_empty());
    }

    #[test]
    fn parser_does_not_pick_up_fragments_from_unrelated_chains() {
        // The `forward` chain also has "ct state established,related
        // accept" but the parser must only count fragments inside
        // the killswitch chain. Confirm cross-chain isolation.
        let body = r#"
table inet rustynet {
        chain killswitch {
                type filter hook output priority 0; policy drop;
        }
        chain forward {
                ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present);
        assert!(chains.iter().any(|c| c == "killswitch"));
        // Neither reviewed fragment was inside the killswitch chain,
        // so frags must stay empty even though `forward` has one.
        assert!(
            frags.is_empty(),
            "forward-chain fragments must not leak into killswitch frag list: {frags:?}"
        );
    }

    #[test]
    fn parser_handles_multiple_unrelated_tables_before_rustynet() {
        let body = r#"
table inet filter { chain input {} }
table ip nat { chain postrouting {} }
table inet rustynet {
        chain killswitch {
                oifname "lo" accept
                ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept
        }
        chain forward {}
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present);
        assert_eq!(chains.len(), 2);
        assert_eq!(frags.len(), 4);
    }

    #[test]
    fn parser_returns_absent_on_empty_input() {
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch("");
        assert!(!present);
        assert!(chains.is_empty());
        assert!(frags.is_empty());
    }

    #[test]
    fn parser_accepts_generation_rotated_table_name() {
        // The runtime's `phase10::LiveSystem::firewall_table_name`
        // programs the killswitch under a generation-rotated form
        // (`rustynet_g<N>`) so it can swap between generations
        // atomically. The verifier must accept that rotated form;
        // otherwise every post-apply state would falsely report
        // "table missing" and any unit restart would hit the L8
        // leak-window drift gate even though the killswitch is in
        // fact programmed.
        let body = r#"
table inet rustynet_g5 {
        chain killswitch {
                type filter hook output priority 0; policy drop;
                oifname "lo" accept
                ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept
                ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept
        }
        chain forward {
                type filter hook forward priority 0; policy drop;
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(
            present,
            "rotated `rustynet_g<N>` table must be detected as the reviewed killswitch"
        );
        assert!(chains.iter().any(|c| c == "killswitch"));
        assert!(chains.iter().any(|c| c == "forward"));
        assert_eq!(frags.len(), 4, "all reviewed fragments must match");
    }

    #[test]
    fn parser_rejects_lookalike_table_names() {
        // Tables that share the `rustynet` prefix but are NOT the
        // reviewed killswitch (e.g. the NAT table `rustynet_nat_g1`,
        // or a typo'd `rustynetfoo`) must not be conflated.
        let body = r#"
table ip rustynet_nat_g1 {
        chain postrouting { type nat hook postrouting priority 100; }
}
table inet rustynet_nat_g1 {
        chain killswitch { oifname "lo" accept }
}
table inet rustynetfoo {
        chain killswitch { oifname "lo" accept }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(
            !present,
            "lookalike tables must not be matched as the reviewed killswitch: chains={chains:?} frags={frags:?}"
        );
    }

    #[test]
    fn header_matcher_pins_exact_grammar() {
        // Canonical form.
        assert!(line_is_reviewed_table_header("table inet rustynet {"));
        // Generation-rotated forms.
        assert!(line_is_reviewed_table_header("table inet rustynet_g0 {"));
        assert!(line_is_reviewed_table_header("table inet rustynet_g7 {"));
        assert!(line_is_reviewed_table_header("table inet rustynet_g42 {"));
        // Tab between name and `{` is acceptable (nft pretty-prints
        // with spaces but custom dumps may use tabs).
        assert!(line_is_reviewed_table_header("table inet rustynet_g1\t{"));
        // Negatives: wrong family, wrong base name, missing brace,
        // missing digits, lookalike prefix.
        assert!(!line_is_reviewed_table_header("table ip rustynet {"));
        assert!(!line_is_reviewed_table_header(
            "table inet rustynet_nat_g1 {"
        ));
        assert!(!line_is_reviewed_table_header("table inet rustynetfoo {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet_g {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet_gX {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet"));
        assert!(!line_is_reviewed_table_header("# table inet rustynet {"));
    }

    #[test]
    fn reviewed_required_chains_pinned_at_two() {
        // Snapshot: the reviewed required-chain list must stay at
        // exactly ["killswitch", "forward"]. Silent extension or
        // removal must trip a named test.
        assert_eq!(REVIEWED_REQUIRED_CHAINS, &["killswitch", "forward"]);
    }

    #[test]
    fn reviewed_required_fragments_pinned_at_four() {
        assert_eq!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.len(), 4);
        assert!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.contains(&"oifname \"lo\" accept"));
        assert!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.contains(
            &"ct state established,related meta nfproto ipv4 tcp dport != { 53, 853 } accept"
        ));
        assert!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.contains(
            &"ct state established,related meta nfproto ipv4 udp dport != { 53, 853 } accept"
        ));
        assert!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.contains(
            &"ct state established,related meta nfproto ipv4 meta l4proto != { tcp, udp } accept"
        ));
    }

    /// AQ-253: the boot killswitch's established/related bodies must BE the
    /// runtime generator's shared list (no drift between the boot-time chain
    /// and the daemon's killswitch/forward chains), and each reviewed
    /// fragment must remain the exact `join(" ")` rendering of the
    /// corresponding shared rule — otherwise the L8 verifier's substring
    /// match and what the code actually installs diverge.
    #[test]
    fn boot_established_related_bodies_match_phase10_shared_list_and_fragments() {
        let bodies = boot_established_related_rule_bodies();
        assert_eq!(
            bodies,
            crate::phase10::LinuxCommandSystem::established_related_accept_tokens(),
            "boot established/related bodies must be the phase10 shared list verbatim"
        );
        assert_eq!(
            bodies.len(),
            3,
            "established/related must stay three scoped rules"
        );
        for (index, body) in bodies.iter().enumerate() {
            let fragment = REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS
                .get(index + 1)
                .expect("reviewed fragments pin loopback + the three established/related rules");
            assert_eq!(
                body.join(" "),
                *fragment,
                "reviewed fragment #{index} drifted from the shared rule rendering"
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collector_off_linux_marks_table_absent_with_clear_blocker() {
        let report = collect_linux_killswitch_boot_report("rustynet0");
        assert!(!report.snapshot.table_present);
        assert!(!report.snapshot.tunnel_interface_present);
        assert!(report.snapshot.ruleset_source.contains("off-Linux"));
        // overall_ok must be false because the reviewed chains are
        // missing even though no leak-window reason fires.
        assert!(!report.overall_ok);
    }

    // ---- boot killswitch constants ----------------------------------------

    #[test]
    fn boot_killswitch_table_name_pinned() {
        // The disconnect-cleanup path intentionally preserves any table
        // whose name does not match `rustynet_g*` or `rustynet_nat_g*`,
        // which keeps `rustynet_boot` alive across daemon teardown.
        // Renaming the constant would silently break that invariant.
        assert_eq!(BOOT_KILLSWITCH_TABLE, "rustynet_boot");
    }

    // ---- BootSshCidr::parse -----------------------------------------------

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv4_host() {
        let c = BootSshCidr::parse("192.168.1.5/32").unwrap();
        assert_eq!(c.family, "ip");
        assert_eq!(c.cidr, "192.168.1.5/32");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv4_subnet() {
        let c = BootSshCidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(c.family, "ip");
        assert_eq!(c.cidr, "10.0.0.0/8");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv6_host() {
        let c = BootSshCidr::parse("fd00::1/128").unwrap();
        assert_eq!(c.family, "ip6");
        assert_eq!(c.cidr, "fd00::1/128");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv6_subnet() {
        let c = BootSshCidr::parse("fd00::/64").unwrap();
        assert_eq!(c.family, "ip6");
        assert_eq!(c.cidr, "fd00::/64");
    }

    #[test]
    fn boot_ssh_cidr_parse_trims_whitespace() {
        let c = BootSshCidr::parse("  192.168.0.0/16  ").unwrap();
        assert_eq!(c.family, "ip");
        // The stored cidr is the trimmed input.
        assert_eq!(c.cidr, "192.168.0.0/16");
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_empty() {
        assert!(BootSshCidr::parse("").is_err());
        assert!(BootSshCidr::parse("   ").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_no_slash() {
        assert!(BootSshCidr::parse("192.168.1.1").is_err());
        assert!(BootSshCidr::parse("fd00::1").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_bad_ip() {
        assert!(BootSshCidr::parse("999.0.0.0/8").is_err());
        assert!(BootSshCidr::parse("notanip/24").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_bad_prefix_non_numeric() {
        assert!(BootSshCidr::parse("192.168.0.0/abc").is_err());
        assert!(BootSshCidr::parse("fd00::/xyz").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_ipv4_prefix_over_32() {
        assert!(BootSshCidr::parse("192.168.0.0/33").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_ipv6_prefix_over_128() {
        assert!(BootSshCidr::parse("fd00::/129").is_err());
    }

    // ---- install_linux_boot_killswitch off-Linux no-op --------------------

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn install_boot_killswitch_off_linux_is_noop() {
        // Off-Linux: must return Ok without touching any nft state.
        let cidrs = vec![
            BootSshCidr::parse("192.168.0.0/16").unwrap(),
            BootSshCidr::parse("fd00::/64").unwrap(),
        ];
        let endpoints = vec![
            BootTraversalEndpoint::parse("74.125.250.129:19302").unwrap(),
            BootTraversalEndpoint::parse("[2001:db8::1]:3478").unwrap(),
        ];
        let result =
            install_linux_boot_killswitch("rustynet0", true, &cidrs, Some(51820), &endpoints);
        assert!(
            result.is_ok(),
            "off-Linux install must be a no-op: {result:?}"
        );
    }

    #[test]
    fn boot_killswitch_emits_wg_listen_port_rules() {
        // Pin against the regression where the boot chain (which hooks
        // `output` priority 0 alongside the daemon's generation-rotated
        // chain) had no outbound-UDP accept for the WireGuard listen
        // port. Without that rule, every WG handshake the daemon emits
        // during the pre-`path_live_proven` window returns EPERM from
        // `sendto(2)` because this boot chain's `policy drop` still
        // applies even when the daemon's chain would have accepted.
        // (Formerly a source-text pin; now the builder's actual output,
        // which cannot drift from what the chain really programs.)
        let rules = super::boot_killswitch_rule_argvs("rustynet0", false, &[], Some(51820), &[]);
        let dport = rules
            .iter()
            .position(|argv| argv.windows(3).any(|w| w == ["udp", "dport", "51820"]));
        let sport = rules
            .iter()
            .position(|argv| argv.windows(3).any(|w| w == ["udp", "sport", "51820"]));
        let (dport, sport) = (
            dport.expect("dport 51820 rule"),
            sport.expect("sport 51820 rule"),
        );
        assert_ne!(dport, sport, "dport and sport are two distinct rules");
        for at in [dport, sport] {
            let argv = rules.get(at).expect("positioned rule exists");
            assert_eq!(
                argv.last().map(String::as_str),
                Some("accept"),
                "the port allows must accept: {argv:?}"
            );
        }
        // The None caller must skip the port rules entirely (the
        // established/related DNS scoping also matches udp dport, so pin the
        // exact listen-port shape).
        let rules = super::boot_killswitch_rule_argvs("rustynet0", false, &[], None, &[]);
        assert!(
            !rules
                .iter()
                .any(|argv| argv.windows(3).any(|w| w == ["udp", "dport", "51820"])),
            "wg_listen_port=None must emit no udp/dport 51820 rule: {rules:#?}"
        );
    }

    #[test]
    fn boot_traversal_endpoint_parses_and_rejects_malformed() {
        let v4 = BootTraversalEndpoint::parse("74.125.250.129:19302").expect("ipv4 endpoint");
        assert_eq!(v4.family, "ip");
        assert_eq!(v4.addr, "74.125.250.129");
        assert_eq!(v4.port, 19302);

        let v6 = BootTraversalEndpoint::parse("[2001:db8::1]:3478").expect("ipv6 endpoint");
        assert_eq!(v6.family, "ip6");
        assert_eq!(v6.port, 3478);

        // Fail closed on anything malformed rather than silently skipping:
        // a dropped entry would leave the operator believing STUN egress is
        // permitted when the boot chain still vetoes it.
        for bad in ["", "not-an-endpoint", "74.125.250.129", "74.125.250.129:0"] {
            assert!(
                BootTraversalEndpoint::parse(bad).is_err(),
                "malformed traversal endpoint must be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn boot_killswitch_emits_traversal_endpoint_rules() {
        // Pin against the regression this fixes: the traversal-bootstrap
        // allow-list (the STUN servers) was emitted only into the daemon's
        // generation-rotated table, never into this boot chain. Both hook
        // `output` at priority 0, so the boot chain's `policy drop` vetoed
        // every STUN datagram the daemon's table accepted, leaving
        // srflx_candidates permanently 0 and NAT traversal impossible.
        // Measured on a real two-network lab 2026-07-29. (Formerly a
        // source-text pin; now the builder's actual output.)
        let endpoints =
            vec![super::BootTraversalEndpoint::parse("74.125.250.129:19302").expect("endpoint")];
        let rules = super::boot_killswitch_rule_argvs("rustynet0", false, &[], None, &endpoints);
        let matches: Vec<_> = rules
            .iter()
            .filter(|argv| {
                argv.windows(3)
                    .any(|w| w == ["ip", "daddr", "74.125.250.129"])
            })
            .collect();
        assert_eq!(
            matches.len(),
            endpoints.len(),
            "one pinhole per endpoint, exact destination address: {rules:#?}"
        );
        for argv in &matches {
            assert!(
                argv.windows(3).any(|w| w == ["udp", "dport", "19302"]),
                "the STUN pinhole must match the endpoint's exact port: {argv:?}"
            );
        }
    }

    #[test]
    fn boot_killswitch_allows_wireguard_by_source_port() {
        // Pin against the regression this fixes: the boot chain allowed
        // outbound WireGuard only by DESTINATION port, which silently assumes
        // every peer listens on our own listen port. That holds on a LAN and
        // is exactly what NAT traversal breaks -- a peer reached at its
        // server-reflexive candidate sits on an arbitrary NAT-mapped port, so
        // the handshake datagram was dropped with EPERM and traversal could
        // never complete. Measured on a real two-network lab 2026-07-29:
        // `send_to failed for 51.186.254.100:44883: Operation not permitted`.
        let rules = super::boot_killswitch_rule_argvs("rustynet0", false, &[], Some(51820), &[]);
        assert!(
            rules
                .iter()
                .any(|argv| argv.windows(3).any(|w| w == ["udp", "sport", "51820"])),
            "the boot chain must emit a `sport` match so outbound WireGuard to a \
             NAT-mapped peer endpoint is permitted: {rules:#?}"
        );
    }

    /// The boot installer is the ONE firewall-enforcement path that execs
    /// `nft` DIRECTLY (not through the privileged helper's argv allowlist,
    /// whose `is_interface_name` gate covers every runtime rule shape). The
    /// interface name therefore must be validated BEFORE it becomes an nft
    /// argv token: nft concatenates its arguments into one command line and
    /// parses them as grammar, so an unvalidated value could add match terms
    /// or verdicts to the boot chain's rules.
    ///
    /// The value is operator-reachable from real config: the reviewed unit
    /// (`scripts/systemd/rustynetd.service`) interpolates
    /// `${RUSTYNET_WG_INTERFACE}` into `--iface` on the ExecStartPre line, so
    /// `/etc/default/rustynetd` reaches this argv verbatim (systemd's
    /// `${VAR}` form passes the whole expansion as ONE argument).
    ///
    /// The gate mirrors the runtime path's `validate_net_device_name`
    /// character class exactly ([A-Za-z0-9_-], 1..=15) so boot and runtime
    /// cannot drift apart on what an interface name may contain. Validation
    /// errors fire before ANY nft exec on every host OS, so this test is
    /// safe to run off-Linux too; the negative cases never reach exec even
    /// on Linux.
    #[test]
    fn boot_killswitch_rejects_injectable_interface_name_before_nft_exec() {
        for hostile in [
            "rustynet0 accept",
            "rustynet0; drop",
            "",
            "rustynet 0",
            "rustynet0\taccept",
            "a".repeat(16).as_str(),
            "rusty.net0",
        ] {
            let result = super::install_linux_boot_killswitch(hostile, false, &[], None, &[]);
            let err = result.expect_err(
                "an interface name outside the reviewed class must be refused \
                 before any nft argv is built",
            );
            assert!(
                err.contains("invalid boot killswitch interface name"),
                "refusal must name the offending input: {err}"
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn boot_killswitch_accepts_canonical_interface_name() {
        // Off-Linux the installer is a no-op after validation, so the
        // positive path is observable here without touching host state. The
        // canonical name must keep passing the gate or every Linux node
        // fails closed at ExecStartPre.
        super::install_linux_boot_killswitch("rustynet0", false, &[], None, &[])
            .expect("the canonical tunnel interface name must pass the boot gate");
    }

    /// AQ-256 (review mutant A11): with an active substrate transit the boot
    /// installer refuses a missing or zero `--wg-listen-port` BEFORE it execs
    /// anything. The interface name is deliberately invalid, so a regression
    /// that dropped the port check would fail on the interface gate instead
    /// (a different message, still before any nft exec) — this test never
    /// runs nft.
    #[cfg(all(target_os = "linux", feature = "lab-substrate"))]
    #[test]
    fn boot_installer_with_transit_requires_the_wireguard_listen_port() {
        let transit = crate::lab_substrate_transit::parse_attestation(
            "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n\
             peer=192.168.122.31\n",
        )
        .expect("test attestation parses");
        for port in [None, Some(0)] {
            let err = super::install_linux_boot_killswitch_with_substrate_transit(
                "not a valid iface!",
                false,
                &[],
                port,
                &[],
                Some(&transit),
            )
            .expect_err("a transit boot install without the port must refuse");
            assert!(err.contains("--wg-listen-port"), "{port:?}: {err}");
            assert!(
                err.contains("re-run cross_network_substrate_setup"),
                "{err}"
            );
        }
        // Without a transit nothing changes: the same call reaches the
        // unchanged installer, whose interface gate refuses (no nft exec).
        let err = super::install_linux_boot_killswitch_with_substrate_transit(
            "not a valid iface!",
            false,
            &[],
            None,
            &[],
            None,
        )
        .expect_err("the interface gate still applies");
        assert!(
            err.contains("invalid boot killswitch interface name"),
            "{err}"
        );
    }

    // ---- u42-r1 fix: boot transit counters must see established packets ----
    //
    // Root cause of the u42-r1 security_audit_validation failure: the boot
    // installer APPENDED the substrate transit rules BELOW the
    // established/related accepts, so a transit counter only ever saw the
    // FIRST packet of each NEW conntrack flow. The vxlan encapsulation
    // collapses both directions of a peer pair into ONE bidirectional
    // conntrack flow (inner WG 51820->51820, outer sport hash fixed per
    // flow), the persistent WireGuard keepalive keeps it established
    // forever, and on the responder side of a pair the boot counter sat
    // frozen at its boot-time value no matter how much transit flowed.
    // The fix splices the transit argvs directly after the loopback accept,
    // BEFORE the established trio — matching the runtime emitter's
    // generation-table order — so the boot counters see every packet,
    // responder side included.

    /// The loopback rule's index in a boot argv sequence.
    fn loopback_index(rule_argvs: &[Vec<String>]) -> usize {
        rule_argvs
            .iter()
            .position(|argv| {
                argv.windows(2).any(|pair| {
                    pair.first().map(String::as_str) == Some("oifname")
                        && pair.get(1).map(String::as_str) == Some("lo")
                }) && argv.last().map(String::as_str) == Some("accept")
            })
            .expect("boot chain must have a loopback accept rule")
    }

    /// The first established/related rule's index in a boot argv sequence.
    fn first_established_index(rule_argvs: &[Vec<String>]) -> usize {
        rule_argvs
            .iter()
            .position(|argv| {
                argv.iter()
                    .any(|token| token.contains("established,related"))
            })
            .expect("boot chain must have established/related rules")
    }

    /// The transit rules' indexes in a boot argv sequence. Two of the three
    /// callers are Linux-feature-gated, so other builds legitimately see no
    /// caller.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "lab-substrate")),
        allow(dead_code)
    )]
    fn transit_indexes(rule_argvs: &[Vec<String>]) -> Vec<usize> {
        rule_argvs
            .iter()
            .enumerate()
            .filter(|(_, argv)| {
                argv.iter()
                    .any(|token| *token == "rustynet_substrate_transit")
            })
            .map(|(index, _)| index)
            .collect()
    }

    #[cfg(all(target_os = "linux", feature = "lab-substrate"))]
    fn two_peer_attestation() -> crate::lab_substrate_transit::SubstrateTransit {
        crate::lab_substrate_transit::parse_attestation(
            "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n\
             peer=192.168.0.32\npeer=192.168.122.31\n",
        )
        .expect("two-peer test attestation parses")
    }

    /// THE regression pin: with an active substrate transit the boot chain's
    /// transit rules sit AFTER the loopback accept and BEFORE the
    /// established/related trio, contiguous, one per peer. Before the fix
    /// they were appended at the very end, which froze the responder-side
    /// boot counters (u42-r1 security_audit_validation FAIL).
    #[test]
    #[cfg(all(target_os = "linux", feature = "lab-substrate"))]
    fn boot_transit_rules_precede_established_rules() {
        let transit = two_peer_attestation();
        let sequence = super::boot_killswitch_substrate_rule_argv_sequence(
            "rustynet0",
            false,
            &[],
            Some(51820),
            &[],
            Some(&transit),
        );
        let lo = loopback_index(&sequence);
        let established = first_established_index(&sequence);
        let transit_at = transit_indexes(&sequence);
        assert_eq!(
            transit_at.len(),
            transit.peers().len(),
            "one transit rule per peer: {sequence:#?}"
        );
        assert_eq!(
            transit_at.first().copied(),
            Some(lo + 1),
            "the transit rules must start directly after the loopback accept"
        );
        assert_eq!(
            transit_at.last().copied().map(|at| at + 1),
            Some(established),
            "the established/related trio must come directly after the transit rules"
        );
        for (argv, peer) in transit_at
            .iter()
            .filter_map(|&at| sequence.get(at))
            .zip(transit.peers())
        {
            assert!(
                argv.iter().any(|token| token.as_str() == peer.to_string()),
                "transit rule must be pinned to its peer address {peer}: {argv:?}"
            );
        }
    }

    /// With no attestation the sequence is exactly the plain boot chain —
    /// no transit rules spliced in, nothing else moved.
    #[test]
    #[cfg(all(target_os = "linux", feature = "lab-substrate"))]
    fn boot_sequence_without_transit_is_the_plain_chain() {
        let plain = super::boot_killswitch_rule_argvs("rustynet0", false, &[], Some(51820), &[]);
        let sequence = super::boot_killswitch_substrate_rule_argv_sequence(
            "rustynet0",
            false,
            &[],
            Some(51820),
            &[],
            None,
        );
        assert_eq!(sequence, plain);
        assert!(
            transit_indexes(&sequence).is_empty(),
            "no transit rules without an attestation"
        );
    }

    /// The plain boot chain keeps its reviewed order: loopback first, then
    /// the established/related trio (AQ-70/F2), then the interface and port
    /// allows. Guards the splice helper against ever reordering the base.
    #[test]
    fn boot_chain_base_order_lo_first_then_established() {
        let rules = super::boot_killswitch_rule_argvs("rustynet0", false, &[], None, &[]);
        assert_eq!(loopback_index(&rules), 0, "loopback must stay first");
        assert_eq!(
            first_established_index(&rules),
            1,
            "the established/related trio must directly follow loopback"
        );
        assert_eq!(rules.len(), 5, "lo + 3 established + iface allow");
        let last = rules.last().expect("boot chain is never empty");
        assert!(
            last.contains(&"rustynet0".to_owned()),
            "last rule is the tunnel-interface allow: {last:#?}"
        );
    }

    /// The splice helper inserts directly after the loopback rule and
    /// preserves the rest of the sequence byte-for-byte.
    #[test]
    fn splice_argvs_insert_after_loopback_and_preserve_order() {
        let mut rules = vec![
            vec!["oifname".to_owned(), "lo".to_owned(), "accept".to_owned()],
            vec!["ct".to_owned(), "established".to_owned()],
            vec!["oifname".to_owned(), "rustynet0".to_owned()],
        ];
        let extra = vec![vec!["t1".to_owned()], vec!["t2".to_owned()]];
        super::splice_argvs_after_loopback(&mut rules, extra);
        let flat: Vec<&str> = rules
            .iter()
            .map(|argv| argv.first().map(String::as_str).unwrap_or(""))
            .collect();
        assert_eq!(flat, ["oifname", "t1", "t2", "ct", "oifname"]);
    }

    // ---- boot install prelude: in-place, fail-closed replacement -----------

    /// Every optional rule at once: ssh allow + cidrs, wg listen port,
    /// traversal endpoints. Guards the "no delete anywhere" claim for the
    /// widest install the builder can produce.
    fn full_optional_boot_rules() -> Vec<Vec<String>> {
        let cidrs: Vec<BootSshCidr> = ["192.168.64.0/24", "10.44.0.0/16"]
            .iter()
            .map(|c| BootSshCidr::parse(c).expect("valid boot ssh cidr"))
            .collect();
        let endpoints: Vec<BootTraversalEndpoint> = ["74.125.250.129:19302", "[2001:db8::1]:19302"]
            .iter()
            .map(|a| BootTraversalEndpoint::parse(a).expect("valid traversal endpoint"))
            .collect();
        boot_killswitch_rule_argvs("rustynet0", true, &cidrs, Some(51820), &endpoints)
    }

    #[test]
    fn boot_install_prelude_is_add_then_policy_drop_chain_then_flush() {
        let prelude = super::boot_killswitch_install_prelude();
        assert_eq!(
            prelude.len(),
            3,
            "prelude = add table, add chain, flush chain"
        );

        // [1] idempotent table add.
        assert_eq!(
            prelude[0],
            [
                "add".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                super::BOOT_KILLSWITCH_TABLE.to_owned()
            ],
            "step 1 must add the table in place: {:#?}",
            prelude[0]
        );

        // [2] chain add that re-asserts the output hook with policy drop.
        assert_eq!(
            &prelude[1][..2],
            ["add", "chain"],
            "step 2 must add the chain in place: {:#?}",
            prelude[1]
        );
        assert!(
            prelude[1].contains(&super::BOOT_KILLSWITCH_TABLE.to_owned())
                && prelude[1].contains(&"killswitch".to_owned()),
            "chain add must target the boot killswitch chain: {:#?}",
            prelude[1]
        );
        for token in [
            "type", "filter", "hook", "output", "priority", "policy", "drop",
        ] {
            assert!(
                prelude[1].iter().any(|t| t == token),
                "chain add must carry `{token}`: {:#?}",
                prelude[1]
            );
        }
        // Adjacent-token pins: `priority` must be exactly `0` and `policy`
        // exactly `drop`, as ADJACENT pairs (a presence check alone let a
        // `priority 0` -> `priority 10` drift mutant survive every test).
        for pair in [("priority", "0"), ("policy", "drop")] {
            assert!(
                prelude[1]
                    .windows(2)
                    .any(|w| w[0] == pair.0 && w[1] == pair.1),
                "chain add must carry the adjacent pair `{} {}`: {:#?}",
                pair.0,
                pair.1,
                prelude[1]
            );
        }

        // [3] flush runs after the policy-drop chain exists.
        assert_eq!(
            &prelude[2][..3],
            ["flush", "chain", "inet"],
            "step 3 must flush the chain: {:#?}",
            prelude[2]
        );
        assert_eq!(prelude[2][3], super::BOOT_KILLSWITCH_TABLE);
        assert_eq!(prelude[2][4], "killswitch");

        // No argv anywhere in the full install (prelude + all optional rules)
        // may contain a delete step.
        let full = super::boot_killswitch_full_install_argv_sequence(&full_optional_boot_rules());
        for argv in &full {
            assert!(
                !argv.iter().any(|t| t == "delete"),
                "install path must never delete: {argv:#?}"
            );
        }
    }

    #[test]
    fn boot_install_policy_drop_chain_is_added_before_flush() {
        let full = super::boot_killswitch_full_install_argv_sequence(&full_optional_boot_rules());
        let add_chain_at = full
            .iter()
            .position(|argv| argv.first().map(String::as_str) == Some("add"))
            .expect("prelude must add the chain");
        let flush_at = full
            .iter()
            .position(|argv| argv.first().map(String::as_str) == Some("flush"))
            .expect("prelude must flush the chain");
        assert!(
            add_chain_at < flush_at,
            "the policy-drop chain must exist BEFORE the flush so the flush \
             happens under drop (fail closed); got add at {add_chain_at}, flush at {flush_at}"
        );
    }

    #[test]
    fn boot_install_executor_composes_prelude_first_then_rules() {
        let rules = boot_killswitch_rule_argvs("rustynet0", false, &[], Some(51820), &[]);
        let prelude = super::boot_killswitch_install_prelude();
        let full = super::boot_killswitch_full_install_argv_sequence(&rules);
        assert!(
            full.len() == prelude.len() + rules.len()
                && full[..prelude.len()] == prelude[..]
                && full[prelude.len()..] == rules[..],
            "the full install sequence must be prelude followed by the rules \
             (prelude can never trail the rules)"
        );
    }

    #[test]
    fn boot_install_executor_runs_every_step_in_order() {
        let rules = full_optional_boot_rules();
        let full = super::boot_killswitch_full_install_argv_sequence(&rules);
        let mut seen: Vec<Vec<String>> = Vec::new();
        super::run_boot_killswitch_argv_sequence(&full, |argv| {
            seen.push(argv.to_vec());
            Ok(())
        })
        .expect("recording runner never fails");
        assert_eq!(seen, full, "executor must replay every argv in order");
    }

    #[test]
    fn boot_install_executor_aborts_at_first_failing_step() {
        let full = super::boot_killswitch_full_install_argv_sequence(&full_optional_boot_rules());
        for k in 0..full.len() {
            let mut seen = 0usize;
            let mut called = 0usize;
            let err = super::run_boot_killswitch_argv_sequence(&full, |_argv| {
                called += 1;
                if seen == k {
                    Err(format!("injected failure at step {k}"))
                } else {
                    seen += 1;
                    Ok(())
                }
            })
            .expect_err("a failing step must abort the install");
            assert_eq!(seen, k, "no step after the first failure may run (k={k})");
            assert_eq!(
                called,
                k + 1,
                "exactly k+1 runner invocations for a failure at step k — a retry \
                 would invoke the failing step twice (k={k})"
            );
            assert_eq!(
                err,
                format!("injected failure at step {k}"),
                "the runner's error must be returned verbatim (k={k})"
            );
        }
        // And no step in the sequence is ever a delete, so the abort can
        // never leave the table absent.
        for argv in &full {
            assert!(
                !argv.iter().any(|t| t == "delete"),
                "fail-closed install must never delete: {argv:#?}"
            );
        }
    }

    // ---- R1: the boot install runtime guard ---------------------------------

    #[test]
    fn boot_install_guard_refuses_destructive_verbs_without_running_them() {
        let owned =
            |argv: &[&str]| -> Vec<String> { argv.iter().map(|s| (*s).to_owned()).collect() };
        // `concat!("del", "ete")` is the review's M9 shape: a split source
        // string that yields the same whole runtime token.
        let evil: Vec<Vec<String>> = vec![
            owned(&["delete", "table", "inet", super::BOOT_KILLSWITCH_TABLE]),
            owned(&[
                "delete",
                "chain",
                "inet",
                super::BOOT_KILLSWITCH_TABLE,
                "killswitch",
            ]),
            owned(&["destroy", "table", "inet", super::BOOT_KILLSWITCH_TABLE]),
            owned(&["flush", "table", "inet", super::BOOT_KILLSWITCH_TABLE]),
            owned(&["flush", "ruleset"]),
            owned(&[
                concat!("del", "ete"),
                "table",
                "inet",
                super::BOOT_KILLSWITCH_TABLE,
            ]),
            // The verb is still recognized after a program token + options.
            owned(&[
                "nft",
                "-a",
                "delete",
                "table",
                "inet",
                super::BOOT_KILLSWITCH_TABLE,
            ]),
        ];
        for argv in &evil {
            let mut calls = 0usize;
            let err = super::run_boot_killswitch_argv_sequence(std::slice::from_ref(argv), |_| {
                calls += 1;
                Ok(())
            })
            .expect_err("the guard must refuse a destructive nft verb");
            assert_eq!(
                calls, 0,
                "the runner must NEVER be invoked for a refused argv: {argv:?}"
            );
            for token in argv {
                assert!(
                    err.contains(token.as_str()),
                    "guard error must name the offending argv (missing `{token}`): {err}"
                );
            }
        }
    }

    #[test]
    fn boot_install_guard_allows_flush_chain_and_real_sequence_unchanged() {
        let owned =
            |argv: &[&str]| -> Vec<String> { argv.iter().map(|s| (*s).to_owned()).collect() };
        // `flush chain` is the only flush shape the install uses and the
        // only one the guard allows.
        let flush_chain = owned(&[
            "flush",
            "chain",
            "inet",
            super::BOOT_KILLSWITCH_TABLE,
            "killswitch",
        ]);
        let mut calls = 0usize;
        super::run_boot_killswitch_argv_sequence(&[flush_chain], |_| {
            calls += 1;
            Ok(())
        })
        .expect("`flush chain` must pass the guard");
        assert_eq!(calls, 1);

        // The real install sequence passes the guard unchanged: every step
        // reaches the runner, in order, unmodified.
        let full = super::boot_killswitch_full_install_argv_sequence(&full_optional_boot_rules());
        let mut seen: Vec<Vec<String>> = Vec::new();
        super::run_boot_killswitch_argv_sequence(&full, |argv| {
            seen.push(argv.to_vec());
            Ok(())
        })
        .expect("the real install sequence must pass the guard unchanged");
        assert_eq!(
            seen, full,
            "the guard must not rewrite, reorder or drop any real step"
        );
    }

    // ---- R4: the add-chain remedy mapping is cross-platform -----------------

    #[test]
    fn boot_install_add_chain_remedy_maps_only_add_chain_failures() {
        let prelude = super::boot_killswitch_install_prelude();
        let chain_argv = &prelude[1];
        assert!(
            super::is_add_chain_argv(chain_argv),
            "prelude step 2 must be recognized as `add chain`: {chain_argv:?}"
        );

        // Polarity 1: a failing `add chain` step gains the remedy.
        let base = "nft add chain failed (exit 1)".to_owned();
        let mapped = super::map_boot_install_step_error(chain_argv, base.clone());
        assert_ne!(mapped, base, "an add-chain failure must gain the remedy");
        assert!(
            mapped.starts_with(base.as_str())
                && mapped.contains("`nft delete table inet rustynet_boot`")
                && mapped.contains("never deletes the table"),
            "the remedy must keep the original error and name the manual \
             remedy verbatim: {mapped}"
        );

        // Polarity 2: every other failing argv passes through verbatim.
        let flush_argv = &prelude[2];
        assert!(!super::is_add_chain_argv(flush_argv));
        assert_eq!(
            super::map_boot_install_step_error(flush_argv, base.clone()),
            base,
            "a non-chain failure must pass through verbatim"
        );
        let rule_argvvs =
            super::boot_killswitch_rule_argvs("rustynet0", false, &[], Some(51820), &[]);
        let rule_argv = rule_argvvs.first().expect("at least one rule argv");
        assert!(
            !super::is_add_chain_argv(rule_argv),
            "a rule argv is not `add chain`: {rule_argv:?}"
        );
        assert_eq!(
            super::map_boot_install_step_error(rule_argv, base.clone()),
            base,
            "a rule failure must pass through verbatim"
        );
    }

    /// Source pin: the install path (everything before the test module,
    /// comments excluded) must not construct a delete argv, the Linux
    /// executor must keep exactly ONE process spawn (the single argv-only
    /// `nft` helper — a second spawn could run verbs the runtime guard
    /// never inspects), and it must route through the prelude-composing
    /// sequence.  A re-introduced `delete table` step or a bypass of the
    /// prelude fails this test.  The impl/test split is anchored to the
    /// real test-module DECLARATION: a `#[cfg(test)]` mention inside a
    /// comment used to truncate the guarded region silently, and a stray
    /// occurrence before the declaration now fails loudly instead.
    #[test]
    fn boot_install_source_pins_no_delete_and_prelude_composition() {
        let source = include_str!("linux_killswitch_boot.rs");
        const TEST_MODULE_DECL: &str = "\n#[cfg(test)]\nmod tests";
        let split_at = source
            .find(TEST_MODULE_DECL)
            .expect("test module declaration must exist");
        let impl_text = &source[..split_at];
        assert_eq!(
            source[..split_at + TEST_MODULE_DECL.len()]
                .matches("#[cfg(test)]")
                .count(),
            1,
            "the test-module declaration must be the only `#[cfg(test)]` up to \
             the split (an earlier stray occurrence would have truncated the \
             guarded region silently)"
        );
        for (idx, line) in impl_text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue; // comments may discuss the manual remedy
            }
            assert!(
                !line.contains("\"delete\""),
                "install path must never build a delete argv (line {}): {line}",
                idx + 1
            );
        }
        let executor_text = impl_text
            .split("fn install_boot_killswitch_rule_sequence")
            .nth(1)
            .expect("the Linux executor must exist")
            .split("\nfn ")
            .next()
            .expect("the executor must be followed by a top-level item");
        assert_eq!(
            executor_text.matches("Command::new").count(),
            1,
            "the install executor must keep exactly one process spawn (the \
             argv-only `nft` helper); a second spawn could run destructive \
             verbs the runtime guard never inspects"
        );
        assert!(
            impl_text.contains("boot_killswitch_full_install_argv_sequence(rule_argvs)"),
            "the Linux executor must compose prelude + rules through the \
             shared full-sequence builder"
        );
        assert!(
            impl_text.contains("nft delete table inet rustynet_boot"),
            "the add-chain failure error must name the manual remedy verbatim"
        );
    }
}
