//! PKG-G — bounded, observation-only system diagnostics.
//!
//! This module answers one question for an operator or an automated gate:
//! *"what is this host's networking + firewall + service state right now?"*
//! — without ever touching that state.
//!
//! ## Observation-only guarantee
//!
//! Every diagnostic in this module is read-only **by construction**, not by
//! convention:
//!
//! 1. [`READ_ONLY_COMMANDS`] is a fixed, compile-time table of the *exact*
//!    `(program, argv)` pairs this module is permitted to execute. Every
//!    entry is a read/list/show/query verb (`route show`, `list ruleset`,
//!    `-L -n`, `-s info`, `is-active`, `show interfaces`, ...); none adds,
//!    sets, deletes, flushes, starts, stops, restarts, or enables anything.
//! 2. [`run_read_only`] is the *only* path in this module that can reach a
//!    real subprocess spawn, and it fail-closed rejects (returns
//!    [`CommandOutcome::RejectedNotAllowlisted`], never spawns) any
//!    `(program, args)` that is not an exact match against that table. A
//!    future edit that accidentally introduced a mutating call would be
//!    rejected at runtime, not just at review time.
//! 3. No argv in this module is influenced by external input: the CLI
//!    surface (`rustynet diagnostics`) takes no arguments, so every
//!    invocation this module performs is one of the fixed rows in
//!    [`READ_ONLY_COMMANDS`] — nothing here is assembled from
//!    caller-supplied strings.
//! 4. `tests::observing_never_issues_a_mutating_command` runs the full
//!    report through a capture-seam [`CommandRunner`] fake and asserts
//!    every invocation it recorded is allowlisted — the seam required by
//!    the PKG-G package contract.
//!
//! ## Bounded execution guarantee
//!
//! [`run_read_only`] never blocks past [`DEFAULT_COMMAND_TIMEOUT`]:
//! [`SystemCommandRunner`] spawns the child with piped stdout/stderr drained
//! on background threads (so a full pipe buffer can never deadlock the
//! wait loop), polls `try_wait` against a deadline, and — if the deadline
//! passes — kills and reaps the child and returns
//! [`CommandOutcome::TimedOut`] instead of hanging. A hung or wedged tool
//! (e.g. a stalled kernel netlink query, a firewall daemon under load)
//! can therefore never block the diagnostics report, and by extension
//! never block the CLI command or a caller in an automated gate.
//!
//! The one genuinely I/O-free check (Linux interface enumeration reads
//! `/sys/class/net/*` directly, no subprocess) is bounded trivially: there
//! is no external process to hang.
//!
//! ## Fail-safe parsing
//!
//! Every `parse_*` function in this module is pure (`&str -> T`, no I/O) and
//! never panics: missing, truncated, or garbage input degrades to an empty
//! `Vec`, a conservative default (`false`/`None`/`Unknown`), or a
//! `queried: false` marker — never an `unwrap`/`expect`/index panic. See
//! `tests::*_malformed_input_is_fail_safe` for the coverage.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{DnsResolverInfo, InterfaceDetail, ListeningSocket, Route, ServiceStatus};

#[cfg(target_os = "windows")]
use crate::parse_netstat_listening_sockets_windows;
#[cfg(target_os = "linux")]
use crate::{parse_ip_route_show, parse_ss_listening_sockets};

/// Upper bound on any single external-tool invocation this module performs.
/// Generous for a local read-only query (route table dump, socket list,
/// firewall ruleset listing) while still guaranteeing the caller gets a
/// prompt answer if a tool hangs.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

// The fixed identifiers this module probes for "service status". Not
// user-supplied: these are Rustynet's own registered service identities
// (systemd unit `scripts/systemd/rustynetd.service`, launchd label
// `scripts/launchd/com.rustynet.daemon.plist`, and
// `rustynetd::windows_service::DEFAULT_WINDOWS_SERVICE_NAME`). Kept as
// local constants rather than an import because `rustynet-sysinfo` sits
// below the daemon layer in the dependency graph (§8/§11.2) and must not
// depend on `rustynetd`.
const LINUX_SERVICE_UNIT: &str = "rustynetd";
const MACOS_DAEMON_LABEL: &str = "com.rustynet.daemon";
const WINDOWS_SERVICE_NAME: &str = "RustyNet";

/// The complete, exhaustive table of `(program, argv)` invocations this
/// module is permitted to execute — see the module-level "observation-only
/// guarantee" doc. Every row is compiled unconditionally (regardless of
/// target OS) so `tests::every_allowlist_row_is_recognized` and the
/// negative "a mutating verb is rejected" tests exercise the whole table on
/// any host, not just the one it happened to build on.
const READ_ONLY_COMMANDS: &[(&str, &[&str])] = &[
    // Linux
    ("ip", &["route", "show"]),
    ("ss", &["-tlnp"]),
    ("nft", &["list", "ruleset"]),
    ("iptables", &["-L", "-n"]),
    ("systemctl", &["is-active", LINUX_SERVICE_UNIT]),
    // macOS
    ("ifconfig", &[]),
    ("netstat", &["-rn"]),
    ("netstat", &["-an"]),
    ("scutil", &["--dns"]),
    ("pfctl", &["-s", "info"]),
    ("launchctl", &["list", MACOS_DAEMON_LABEL]),
    // Windows
    ("netsh", &["interface", "ipv4", "show", "interfaces"]),
    ("route", &["print"]),
    ("netstat", &["-ano"]),
    ("netsh", &["interface", "ip", "show", "dns"]),
    ("netsh", &["advfirewall", "show", "allprofiles", "state"]),
    ("sc", &["query", WINDOWS_SERVICE_NAME]),
];

/// `true` iff `(program, args)` exactly matches a row of
/// [`READ_ONLY_COMMANDS`]. The sole gate in [`run_read_only`].
fn is_allowlisted(program: &str, args: &[&str]) -> bool {
    READ_ONLY_COMMANDS
        .iter()
        .any(|(allowed_program, allowed_args)| *allowed_program == program && *allowed_args == args)
}

/// Outcome of a single bounded, allowlist-checked command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// The process exited before the deadline. `stdout`/`stderr` are
    /// captured via lossy UTF-8 conversion; `success` reflects the exit
    /// status.
    Completed {
        stdout: String,
        stderr: String,
        success: bool,
    },
    /// The process did not exit within [`DEFAULT_COMMAND_TIMEOUT`] and was
    /// killed and reaped.
    TimedOut,
    /// The program could not be spawned at all (not installed, PATH
    /// rejects it, permission denied on exec, ...).
    Unavailable,
    /// Rejected before any spawn attempt because `(program, args)` is not
    /// an exact match in [`READ_ONLY_COMMANDS`]. See the module-level
    /// "observation-only guarantee" doc — this is the by-construction
    /// enforcement point.
    RejectedNotAllowlisted,
}

/// Seam every diagnostic in this module runs external tools through.
/// Production code uses [`SystemCommandRunner`]; tests use a recording
/// fake so (a) parser tests can supply canned stdout without spawning a
/// real process and (b) a full report run can assert, after the fact, that
/// every invocation it made was allowlisted (the capture-seam requirement).
pub trait CommandRunner {
    /// Run `program` with `args` and return within `timeout`. Implementors
    /// must not perform the allowlist check themselves — callers only ever
    /// reach this through [`run_read_only`], which already checked it.
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandOutcome;
}

/// The allowlist-checked entry point every `observe_*` function in this
/// module uses. Never spawns anything outside [`READ_ONLY_COMMANDS`].
fn run_read_only(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> CommandOutcome {
    if !is_allowlisted(program, args) {
        return CommandOutcome::RejectedNotAllowlisted;
    }
    runner.run(program, args, timeout)
}

/// Real, bounded process execution. The only [`CommandRunner`] used in
/// production (see [`observe_system_diagnostics`]).
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandOutcome {
        spawn_bounded(program, args, timeout)
    }
}

/// Spawn `program args`, drain stdout/stderr on background threads (so a
/// full pipe buffer can never deadlock the wait loop below), and poll
/// `try_wait` against a deadline. If the deadline passes first, kill and
/// reap the child and return [`CommandOutcome::TimedOut`] instead of
/// blocking. This is the sole process-spawning function in the crate's
/// diagnostics surface; it performs no allowlist check itself (that is
/// [`run_read_only`]'s job) so it can also be exercised directly in tests
/// that verify the timeout mechanism in isolation.
fn spawn_bounded(program: &str, args: &[&str], timeout: Duration) -> CommandOutcome {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return CommandOutcome::Unavailable,
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();

    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = stdout_tx.send(buf);
    });
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = stderr_tx.send(buf);
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break None;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };

    let Some(status) = status else {
        // Timed out (or `try_wait` itself errored): kill + reap so no
        // zombie/hang leaks. Killing the child closes its stdout/stderr
        // pipes, which lets the drain threads' `read_to_end` return; we
        // don't join them (a diagnostic tool has no need to wait on that),
        // they exit on their own shortly after.
        let _ = child.kill();
        let _ = child.wait();
        return CommandOutcome::TimedOut;
    };

    // The child already exited, so its pipes are already closed; these
    // recv calls return almost immediately. The timeout is still a hard
    // bound rather than an indefinite block, matching the "never hangs"
    // guarantee even in this branch.
    let stdout_bytes = stdout_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    let stderr_bytes = stderr_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();

    CommandOutcome::Completed {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        success: status.success(),
    }
}

/// Firewall backend a host is using, as best determined by a read-only
/// status query. `Unknown` is the fail-safe default when no backend could
/// be queried at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    PacketFilter,
    WindowsFirewall,
    Unknown,
}

/// Typed, observation-only firewall status. Never carries the raw ruleset
/// text (only small derived counts + a short summary), so this type is
/// always safe to log or print in full — no risk of dumping a large or
/// address-laden rule dump into a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallStatus {
    pub backend: FirewallBackend,
    /// `true` only when the query tool ran successfully AND reported at
    /// least one active table/chain/profile. Conservatively `false`
    /// (fail-safe) whenever the tool is missing, denied, timed out, or its
    /// output could not be parsed — see `queried` to distinguish "confirmed
    /// inactive" from "could not confirm".
    pub active: bool,
    /// Rule/chain/table count when the backend reports one countable;
    /// `None` when not determinable.
    pub rule_count: Option<u32>,
    /// `true` iff the underlying query tool actually ran and returned
    /// parseable output. `false` means `active`/`rule_count` above are
    /// conservative defaults, not verified observations (e.g. `pfctl -s
    /// info` commonly requires root and returns permission-denied for an
    /// unprivileged caller).
    pub queried: bool,
    /// Short human-readable summary for CLI display; never the raw
    /// ruleset dump.
    pub detail: String,
}

/// One bounded, read-only snapshot of a host's networking + firewall +
/// Rustynet-service state. Build with [`observe_system_diagnostics`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsReport {
    pub interfaces: Vec<InterfaceDetail>,
    pub routes: Vec<Route>,
    pub dns: DnsResolverInfo,
    pub listening_sockets: Vec<ListeningSocket>,
    pub firewall: FirewallStatus,
    /// Status of Rustynet's own daemon service (systemd unit / launchd
    /// label / Windows service — see [`LINUX_SERVICE_UNIT`] and siblings).
    pub service: ServiceStatus,
}

/// Take a full, bounded, observation-only diagnostics snapshot of the
/// current host using real subprocess calls ([`SystemCommandRunner`]).
/// This is the only production entry point; tests use [`observe_with`]
/// with a fake [`CommandRunner`] instead.
pub fn observe_system_diagnostics() -> DiagnosticsReport {
    observe_with(&SystemCommandRunner)
}

/// Take a diagnostics snapshot using the given [`CommandRunner`]. Exposed
/// (rather than kept test-only) so any future caller that wants to inject
/// its own bounded runner (e.g. a different timeout policy) can do so
/// without duplicating the orchestration.
pub fn observe_with(runner: &dyn CommandRunner) -> DiagnosticsReport {
    DiagnosticsReport {
        interfaces: observe_interfaces(runner),
        routes: observe_routes(runner),
        dns: observe_dns(runner),
        listening_sockets: observe_listening_sockets(runner),
        firewall: observe_firewall(runner),
        service: observe_service(runner),
    }
}

// ============================================================================
// Interfaces (+ MTU)
// ============================================================================

/// Linux: no subprocess at all — reads `/sys/class/net/*` directly, so this
/// is bounded trivially (no external process to hang). Parameterized on
/// `root` so it can be pointed at a temp-dir fixture in tests without a
/// real `/sys`.
// Only called from the `#[cfg(target_os = "linux")]` `observe_interfaces`
// below; kept universally compiled (no cfg on the function itself) so it
// is unit-testable on every host, matching this crate's established
// parse/IO split convention.
#[allow(dead_code)]
fn interface_details_from_sysfs_root(root: &std::path::Path) -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return ifaces;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let up = std::fs::read_to_string(path.join("operstate"))
            .map(|s| s.trim() == "up")
            .unwrap_or(false);
        let mac_address = std::fs::read_to_string(path.join("address"))
            .ok()
            .map(|s| s.trim().to_owned());
        let mtu = std::fs::read_to_string(path.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        ifaces.push(InterfaceDetail {
            name,
            up,
            mac_address,
            ip_addresses: Vec::new(),
            mtu,
        });
    }
    ifaces
}

#[cfg(target_os = "linux")]
fn observe_interfaces(_runner: &dyn CommandRunner) -> Vec<InterfaceDetail> {
    interface_details_from_sysfs_root(std::path::Path::new("/sys/class/net"))
}

/// Parse macOS `ifconfig` (no args — lists every interface) output into
/// [`InterfaceDetail`]s. A new interface block starts at a non-indented,
/// non-empty line (`"en0: flags=... mtu 1500"`); `mtu <n>` and `inet <ip>`
/// tokens are picked up from subsequent indented lines. Malformed/missing
/// MTU degrades to `0` rather than a fabricated default, so callers can
/// tell "not reported" from "reported as 0".
#[allow(dead_code)] // only reachable via the macOS `observe_interfaces`; universally compiled for cross-platform testability
fn parse_ifconfig_interface_details(stdout: &str) -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();
    let mut current: Option<InterfaceDetail> = None;

    for line in stdout.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && !line.is_empty() {
            if let Some(iface) = current.take() {
                ifaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_owned();
            current = Some(InterfaceDetail {
                name,
                up: line.contains("UP"),
                mac_address: None,
                ip_addresses: Vec::new(),
                mtu: 0,
            });
            // Deliberately no `continue` here: real `ifconfig` prints
            // `mtu <n>` on this same non-indented header line (e.g. `en0:
            // flags=... mtu 1500`), so this line must also fall through to
            // the shared ether/inet/mtu scan below.
        }
        let Some(iface) = current.as_mut() else {
            continue;
        };
        if let Some(rest) = line.trim().strip_prefix("ether ") {
            iface.mac_address = Some(rest.split_whitespace().next().unwrap_or("").to_owned());
        }
        if let Some(pos) = line.find("inet ") {
            if let Some(addr) = line[pos + "inet ".len()..].split_whitespace().next() {
                iface.ip_addresses.push(addr.to_owned());
            }
        }
        if let Some(pos) = line.find("mtu ") {
            if let Some(mtu) = line[pos + "mtu ".len()..]
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok())
            {
                iface.mtu = mtu;
            }
        }
    }
    if let Some(iface) = current {
        ifaces.push(iface);
    }
    ifaces
}

#[cfg(target_os = "macos")]
fn observe_interfaces(runner: &dyn CommandRunner) -> Vec<InterfaceDetail> {
    match run_read_only(runner, "ifconfig", &[], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_ifconfig_interface_details(&stdout),
        _ => Vec::new(),
    }
}

/// Parse `netsh interface ipv4 show interfaces` output (a fixed-width table
/// `Idx  Met  MTU  State  Name`, header + dashed separator, then one row
/// per interface) into [`InterfaceDetail`]s. The `Name` column may contain
/// spaces, so only the first three whitespace fields are taken positionally
/// and the remainder (after the state token) is rejoined as the name.
/// `netsh` does not report a MAC address or IP addresses for this query, so
/// both are left empty/`None` — a documented gap, not a fabricated value.
#[allow(dead_code)] // only reachable via the Windows `observe_interfaces`; universally compiled for cross-platform testability
fn parse_netsh_show_interfaces(stdout: &str) -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Idx") || trimmed.starts_with("---") {
            continue;
        }
        let mut tokens = trimmed.split_whitespace();
        let Some(_idx) = tokens.next() else {
            continue;
        };
        let Some(_metric) = tokens.next() else {
            continue;
        };
        let Some(mtu_token) = tokens.next() else {
            continue;
        };
        let Some(state) = tokens.next() else {
            continue;
        };
        let name: String = tokens.collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            continue;
        }
        ifaces.push(InterfaceDetail {
            name,
            up: state.eq_ignore_ascii_case("connected"),
            mac_address: None,
            ip_addresses: Vec::new(),
            mtu: mtu_token.parse::<u32>().unwrap_or(0),
        });
    }
    ifaces
}

#[cfg(target_os = "windows")]
fn observe_interfaces(runner: &dyn CommandRunner) -> Vec<InterfaceDetail> {
    match run_read_only(
        runner,
        "netsh",
        &["interface", "ipv4", "show", "interfaces"],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netsh_show_interfaces(&stdout),
        _ => Vec::new(),
    }
}

// ============================================================================
// Routes
// ============================================================================

#[cfg(target_os = "linux")]
fn observe_routes(runner: &dyn CommandRunner) -> Vec<Route> {
    match run_read_only(runner, "ip", &["route", "show"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_ip_route_show(&stdout),
        _ => Vec::new(),
    }
}

/// Parse macOS `netstat -rn` output into [`Route`]s. The first four lines
/// (`Routing tables`, blank, `Internet:`, column header) are skipped; a
/// data row is `destination gateway flags netif [expire]` — 4 whitespace
/// fields (5 when the kernel populates an expire time), destination at
/// index 0, gateway at index 1, interface at index 3. Verified against
/// real `netstat -rn` output (macOS 15), which reliably has 4-5 columns —
/// *not* 6, unlike an earlier same-crate `RouteInfo` parser this
/// deliberately does not copy.
#[allow(dead_code)] // only reachable via the macOS `observe_routes`; universally compiled for cross-platform testability
fn parse_netstat_rn_routes(stdout: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    for line in stdout.lines().skip(4) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            routes.push(Route {
                destination: parts[0].to_owned(),
                gateway: parts[1].to_owned(),
                interface: parts[3].to_owned(),
            });
        }
    }
    routes
}

#[cfg(target_os = "macos")]
fn observe_routes(runner: &dyn CommandRunner) -> Vec<Route> {
    match run_read_only(runner, "netstat", &["-rn"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netstat_rn_routes(&stdout),
        _ => Vec::new(),
    }
}

/// Parse Windows `route print` output into [`Route`]s. Anchored on the
/// `Network Destination ...` column header rather than a fixed line count,
/// because the preceding `Interface List` section grows with the number
/// of NICs on the host; capture starts on the line after that header and
/// stops at the next `===`-only separator (the end of the "Active
/// Routes" block, before "Persistent Routes:"). A row qualifies with at
/// least 4 whitespace fields (`destination netmask gateway interface
/// metric`).
#[allow(dead_code)] // only reachable via the Windows `observe_routes`; universally compiled for cross-platform testability
fn parse_route_print_routes(stdout: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut in_table = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Network Destination") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if trimmed.starts_with('=') {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4 {
            routes.push(Route {
                destination: parts[0].to_owned(),
                gateway: parts[2].to_owned(),
                interface: parts[3].to_owned(),
            });
        }
    }
    routes
}

#[cfg(target_os = "windows")]
fn observe_routes(runner: &dyn CommandRunner) -> Vec<Route> {
    match run_read_only(runner, "route", &["print"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_route_print_routes(&stdout),
        _ => Vec::new(),
    }
}

// ============================================================================
// DNS
// ============================================================================

/// Parse `/etc/resolv.conf` contents into a [`DnsResolverInfo`]: each
/// `nameserver <addr>` line contributes a resolver; each `search <a> <b>`
/// or `domain <name>` line contributes search domain(s). Unknown
/// directives and comment (`#`/`;`) lines are ignored.
#[allow(dead_code)] // only reachable via the Linux `observe_dns`; universally compiled for cross-platform testability
fn parse_resolv_conf(content: &str) -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    let mut search_domains = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(addr) = line.strip_prefix("nameserver ") {
            let addr = addr.trim().to_owned();
            if !addr.is_empty() && !resolvers.contains(&addr) {
                resolvers.push(addr);
            }
        } else if let Some(rest) = line.strip_prefix("search ") {
            for domain in rest.split_whitespace() {
                if !search_domains.contains(&domain.to_owned()) {
                    search_domains.push(domain.to_owned());
                }
            }
        } else if let Some(rest) = line.strip_prefix("domain ") {
            let domain = rest.trim().to_owned();
            if !domain.is_empty() && !search_domains.contains(&domain) {
                search_domains.push(domain);
            }
        }
    }
    DnsResolverInfo {
        resolvers,
        search_domains,
        method: "resolv.conf".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn observe_dns(_runner: &dyn CommandRunner) -> DnsResolverInfo {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|content| parse_resolv_conf(&content))
        .unwrap_or(DnsResolverInfo {
            resolvers: Vec::new(),
            search_domains: Vec::new(),
            method: "resolv.conf".to_owned(),
        })
}

/// Parse macOS `scutil --dns` output into a [`DnsResolverInfo`]. The tool
/// prints one `resolver #n` block per configured scope, each with
/// `nameserver[k] : <addr>` and `search domain[k] : <name>` lines; the same
/// resolver is commonly repeated across scopes, so both lists dedupe by
/// insertion order.
#[allow(dead_code)] // only reachable via the macOS `observe_dns`; universally compiled for cross-platform testability
fn parse_scutil_dns(stdout: &str) -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    let mut search_domains = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver[") {
            if let Some(addr) = rest.split(':').nth(1) {
                let addr = addr.trim().to_owned();
                if !addr.is_empty() && !resolvers.contains(&addr) {
                    resolvers.push(addr);
                }
            }
        } else if let Some(rest) = line.strip_prefix("search domain[") {
            if let Some(domain) = rest.split(':').nth(1) {
                let domain = domain.trim().to_owned();
                if !domain.is_empty() && !search_domains.contains(&domain) {
                    search_domains.push(domain);
                }
            }
        }
    }
    DnsResolverInfo {
        resolvers,
        search_domains,
        method: "scutil --dns".to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn observe_dns(runner: &dyn CommandRunner) -> DnsResolverInfo {
    match run_read_only(runner, "scutil", &["--dns"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_scutil_dns(&stdout),
        _ => DnsResolverInfo {
            resolvers: Vec::new(),
            search_domains: Vec::new(),
            method: "scutil --dns".to_owned(),
        },
    }
}

/// A token "looks like" an IPv4/IPv6 literal for the purposes of the
/// `netsh` DNS-list continuation-line heuristic below: every character is a
/// digit, `.`, or `:` (and at least one is present). Deliberately permissive
/// (it does not fully validate an IP) — false positives just mean a
/// resolver-shaped token gets captured, which is the safe direction for an
/// observation-only diagnostic.
#[allow(dead_code)] // only reachable via `parse_netsh_dns` (Windows); universally compiled for cross-platform testability
fn looks_like_ip_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && token.chars().any(|c| c == '.' || c == ':')
}

/// Parse Windows `netsh interface ip show dns` output into a
/// [`DnsResolverInfo`]. Each interface block has a line containing "DNS
/// Servers" whose trailing token (if IP-shaped) is the first resolver;
/// subsequent lines that are *only* an IP-shaped token are additional
/// resolvers for the same block, until a non-IP line ends the list. No
/// search-domain equivalent is printed by this command, so
/// `search_domains` is always empty for this method.
#[allow(dead_code)] // only reachable via the Windows `observe_dns`; universally compiled for cross-platform testability
fn parse_netsh_dns(stdout: &str) -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    let mut in_server_list = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().contains("dns server") {
            in_server_list = true;
            if let Some(last) = trimmed.split_whitespace().last() {
                if looks_like_ip_token(last) && !resolvers.contains(&last.to_owned()) {
                    resolvers.push(last.to_owned());
                }
            }
            continue;
        }
        if in_server_list {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() == 1 && looks_like_ip_token(tokens[0]) {
                if !resolvers.contains(&tokens[0].to_owned()) {
                    resolvers.push(tokens[0].to_owned());
                }
            } else {
                in_server_list = false;
            }
        }
    }
    DnsResolverInfo {
        resolvers,
        search_domains: Vec::new(),
        method: "netsh interface ip show dns".to_owned(),
    }
}

#[cfg(target_os = "windows")]
fn observe_dns(runner: &dyn CommandRunner) -> DnsResolverInfo {
    match run_read_only(
        runner,
        "netsh",
        &["interface", "ip", "show", "dns"],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netsh_dns(&stdout),
        _ => DnsResolverInfo {
            resolvers: Vec::new(),
            search_domains: Vec::new(),
            method: "netsh interface ip show dns".to_owned(),
        },
    }
}

// ============================================================================
// Listening sockets
// ============================================================================

#[cfg(target_os = "linux")]
fn observe_listening_sockets(runner: &dyn CommandRunner) -> Vec<ListeningSocket> {
    match run_read_only(runner, "ss", &["-tlnp"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_ss_listening_sockets(&stdout),
        _ => Vec::new(),
    }
}

/// Parse macOS `netstat -an` output into [`ListeningSocket`]s.
///
/// This deliberately does **not** reuse this crate's existing
/// `parse_netstat_listening_sockets_macos` (paired with `netstat -tln`):
/// verified against real output on macOS 15, `netstat -tln` silently
/// drops the `-a` behavior (it lists only already-established
/// connections, never listeners), and even given listener rows, that
/// parser checks for the `LISTEN` state inside field 3 — but real BSD
/// `netstat` puts the local `address.port` in field 3 and the state in
/// field 5 (`Proto Recv-Q Send-Q Local-Address Foreign-Address (state)`),
/// so it can never match. Reusing either would make this diagnostic
/// silently report "no listeners" on every macOS host. `netstat -an`
/// lists every socket including listeners; a row qualifies with at least
/// 6 whitespace fields and field 5 containing `LISTEN`.
#[allow(dead_code)] // only reachable via the macOS `observe_listening_sockets`; universally compiled for cross-platform testability
fn parse_netstat_an_listening_macos(stdout: &str) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 && parts[5].contains("LISTEN") {
            if let Some(dot_idx) = parts[3].rfind('.') {
                let port: u16 = parts[3][dot_idx + 1..].parse().unwrap_or(0);
                sockets.push(ListeningSocket {
                    protocol: parts[0].to_owned(),
                    address: parts[3][..dot_idx].to_owned(),
                    port,
                    pid: None,
                    process_name: None,
                });
            }
        }
    }
    sockets
}

#[cfg(target_os = "macos")]
fn observe_listening_sockets(runner: &dyn CommandRunner) -> Vec<ListeningSocket> {
    match run_read_only(runner, "netstat", &["-an"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netstat_an_listening_macos(&stdout),
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn observe_listening_sockets(runner: &dyn CommandRunner) -> Vec<ListeningSocket> {
    match run_read_only(runner, "netstat", &["-ano"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netstat_listening_sockets_windows(&stdout),
        _ => Vec::new(),
    }
}

// ============================================================================
// Firewall status
// ============================================================================

/// Parse `nft list ruleset` output. Counts `table `/`chain ` occurrences as
/// a coarse rule-surface size; any table at all is treated as "active"
/// (nftables with an empty ruleset reports no tables).
#[allow(dead_code)] // only reachable via the Linux `observe_firewall`; universally compiled for cross-platform testability
fn parse_nft_ruleset_status(stdout: &str) -> FirewallStatus {
    let table_count = stdout.matches("table ").count() as u32;
    let chain_count = stdout.matches("chain ").count() as u32;
    FirewallStatus {
        backend: FirewallBackend::Nftables,
        active: table_count > 0,
        rule_count: Some(chain_count),
        queried: true,
        detail: format!("nft: {table_count} table(s), {chain_count} chain(s)"),
    }
}

/// Parse `iptables -L -n` output. Counts `Chain ` header lines; any chain
/// at all is treated as "active" (the three built-in default chains always
/// print even when empty of rules, so this reports backend presence more
/// than rule-load — see `detail`).
#[allow(dead_code)] // only reachable via the Linux `observe_firewall` fallback; universally compiled for cross-platform testability
fn parse_iptables_list_status(stdout: &str) -> FirewallStatus {
    let chain_count = stdout
        .lines()
        .filter(|line| line.starts_with("Chain "))
        .count() as u32;
    FirewallStatus {
        backend: FirewallBackend::Iptables,
        active: chain_count > 0,
        rule_count: Some(chain_count),
        queried: true,
        detail: format!("iptables: {chain_count} chain(s) (built-in chains always present)"),
    }
}

#[cfg(target_os = "linux")]
fn observe_firewall(runner: &dyn CommandRunner) -> FirewallStatus {
    if let CommandOutcome::Completed {
        stdout,
        success: true,
        ..
    } = run_read_only(runner, "nft", &["list", "ruleset"], DEFAULT_COMMAND_TIMEOUT)
    {
        return parse_nft_ruleset_status(&stdout);
    }
    if let CommandOutcome::Completed {
        stdout,
        success: true,
        ..
    } = run_read_only(runner, "iptables", &["-L", "-n"], DEFAULT_COMMAND_TIMEOUT)
    {
        return parse_iptables_list_status(&stdout);
    }
    FirewallStatus {
        backend: FirewallBackend::Unknown,
        active: false,
        rule_count: None,
        queried: false,
        detail: "nft and iptables both unavailable or failed".to_owned(),
    }
}

/// Parse `pfctl -s info` output: the `Status: Enabled`/`Status: Disabled`
/// line drives `active`. `pfctl` requires root for this query; a
/// permission-denied or otherwise failed invocation must not be reported
/// as "confirmed disabled" — that is why the caller only reaches this
/// parser on a successful exit.
#[allow(dead_code)] // only reachable via the macOS `observe_firewall`; universally compiled for cross-platform testability
fn parse_pfctl_info_status(stdout: &str) -> FirewallStatus {
    let enabled = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Status: "))
        .map(|rest| rest.trim_start().starts_with("Enabled"));
    match enabled {
        Some(true) => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: true,
            rule_count: None,
            queried: true,
            detail: "pf: Enabled".to_owned(),
        },
        Some(false) => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: false,
            rule_count: None,
            queried: true,
            detail: "pf: Disabled".to_owned(),
        },
        None => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: false,
            rule_count: None,
            queried: false,
            detail: "pf: no Status line in `pfctl -s info` output".to_owned(),
        },
    }
}

#[cfg(target_os = "macos")]
fn observe_firewall(runner: &dyn CommandRunner) -> FirewallStatus {
    match run_read_only(runner, "pfctl", &["-s", "info"], DEFAULT_COMMAND_TIMEOUT) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_pfctl_info_status(&stdout),
        CommandOutcome::Completed { stderr, .. } => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: false,
            rule_count: None,
            queried: false,
            detail: format!(
                "pfctl -s info failed (commonly requires root): {}",
                stderr.lines().next().unwrap_or("no stderr").trim()
            ),
        },
        CommandOutcome::TimedOut => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: false,
            rule_count: None,
            queried: false,
            detail: "pfctl -s info timed out".to_owned(),
        },
        CommandOutcome::Unavailable | CommandOutcome::RejectedNotAllowlisted => FirewallStatus {
            backend: FirewallBackend::PacketFilter,
            active: false,
            rule_count: None,
            queried: false,
            detail: "pfctl unavailable".to_owned(),
        },
    }
}

/// Parse `netsh advfirewall show allprofiles state` output. Counts
/// `State ON`/`State OFF` occurrences (one per profile: Domain/Private/
/// Public); `active` is `true` iff at least one profile reports ON.
#[allow(dead_code)] // only reachable via the Windows `observe_firewall`; universally compiled for cross-platform testability
fn parse_netsh_advfirewall_state(stdout: &str) -> FirewallStatus {
    let mut on_count: u32 = 0;
    let mut off_count: u32 = 0;
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Real output pads the value with many spaces, e.g.
        // "State                                 ON" — match on the
        // "State" prefix + trimmed trailing token rather than a fixed
        // single-space substring.
        let Some(rest) = trimmed.strip_prefix("State") else {
            continue;
        };
        match rest.trim() {
            "ON" => on_count += 1,
            "OFF" => off_count += 1,
            _ => {}
        }
    }
    if on_count == 0 && off_count == 0 {
        return FirewallStatus {
            backend: FirewallBackend::WindowsFirewall,
            active: false,
            rule_count: None,
            queried: false,
            detail: "no profile State line found in `netsh advfirewall` output".to_owned(),
        };
    }
    FirewallStatus {
        backend: FirewallBackend::WindowsFirewall,
        active: on_count > 0,
        rule_count: Some(on_count),
        queried: true,
        detail: format!("windows firewall: {on_count} profile(s) ON, {off_count} OFF"),
    }
}

#[cfg(target_os = "windows")]
fn observe_firewall(runner: &dyn CommandRunner) -> FirewallStatus {
    match run_read_only(
        runner,
        "netsh",
        &["advfirewall", "show", "allprofiles", "state"],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_netsh_advfirewall_state(&stdout),
        _ => FirewallStatus {
            backend: FirewallBackend::WindowsFirewall,
            active: false,
            rule_count: None,
            queried: false,
            detail: "netsh advfirewall query failed".to_owned(),
        },
    }
}

// ============================================================================
// Rustynet daemon service status
// ============================================================================

#[cfg(target_os = "linux")]
fn observe_service(runner: &dyn CommandRunner) -> ServiceStatus {
    match run_read_only(
        runner,
        "systemctl",
        &["is-active", LINUX_SERVICE_UNIT],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout, success, ..
        } => ServiceStatus {
            running: success,
            status_message: stdout.trim().to_owned(),
        },
        CommandOutcome::TimedOut => ServiceStatus {
            running: false,
            status_message: "systemctl is-active timed out".to_owned(),
        },
        CommandOutcome::Unavailable | CommandOutcome::RejectedNotAllowlisted => ServiceStatus {
            running: false,
            status_message: "systemctl unavailable".to_owned(),
        },
    }
}

/// Parse macOS `launchctl list <label>` output: presence of a `"PID"` key
/// means the job is currently running under launchd (a loaded-but-idle job
/// has no `PID` key). This is a common, if slightly heuristic, reading of
/// launchd's freeform dump — documented as such rather than presented as
/// an exact state machine.
#[allow(dead_code)] // only reachable via the macOS `observe_service`; universally compiled for cross-platform testability
fn parse_launchctl_list_status(stdout: &str) -> ServiceStatus {
    let running = stdout.contains("\"PID\"");
    ServiceStatus {
        running,
        status_message: if running {
            "loaded, PID present".to_owned()
        } else {
            "loaded, no PID (not running)".to_owned()
        },
    }
}

#[cfg(target_os = "macos")]
fn observe_service(runner: &dyn CommandRunner) -> ServiceStatus {
    match run_read_only(
        runner,
        "launchctl",
        &["list", MACOS_DAEMON_LABEL],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_launchctl_list_status(&stdout),
        CommandOutcome::Completed { .. } => ServiceStatus {
            running: false,
            status_message: "not loaded".to_owned(),
        },
        CommandOutcome::TimedOut => ServiceStatus {
            running: false,
            status_message: "launchctl list timed out".to_owned(),
        },
        CommandOutcome::Unavailable | CommandOutcome::RejectedNotAllowlisted => ServiceStatus {
            running: false,
            status_message: "launchctl unavailable".to_owned(),
        },
    }
}

/// Parse Windows `sc query <name>` output: the `STATE` line's second token
/// is a numeric code followed by a name (e.g. `4  RUNNING`); `running` is
/// `true` iff that name is exactly `RUNNING`.
#[allow(dead_code)] // only reachable via the Windows `observe_service`; universally compiled for cross-platform testability
fn parse_sc_query_status(stdout: &str) -> ServiceStatus {
    let state_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("STATE"));
    let Some(line) = state_line else {
        return ServiceStatus {
            running: false,
            status_message: "no STATE line in `sc query` output".to_owned(),
        };
    };
    // "        STATE              : 4  RUNNING"
    let after_colon = line.split(':').nth(1).unwrap_or("").trim();
    let state_name = after_colon
        .split_whitespace()
        .nth(1)
        .unwrap_or("UNKNOWN")
        .to_owned();
    ServiceStatus {
        running: state_name == "RUNNING",
        status_message: state_name,
    }
}

#[cfg(target_os = "windows")]
fn observe_service(runner: &dyn CommandRunner) -> ServiceStatus {
    match run_read_only(
        runner,
        "sc",
        &["query", WINDOWS_SERVICE_NAME],
        DEFAULT_COMMAND_TIMEOUT,
    ) {
        CommandOutcome::Completed {
            stdout,
            success: true,
            ..
        } => parse_sc_query_status(&stdout),
        CommandOutcome::Completed { .. } => ServiceStatus {
            running: false,
            status_message: "service not found".to_owned(),
        },
        CommandOutcome::TimedOut => ServiceStatus {
            running: false,
            status_message: "sc query timed out".to_owned(),
        },
        CommandOutcome::Unavailable | CommandOutcome::RejectedNotAllowlisted => ServiceStatus {
            running: false,
            status_message: "sc unavailable".to_owned(),
        },
    }
}

// ============================================================================
// Rendering (used by the `rustynet diagnostics` CLI surface)
// ============================================================================

/// Render a [`DiagnosticsReport`] as human-readable, indented text for the
/// `rustynet diagnostics` CLI command.
pub fn render_report(report: &DiagnosticsReport) -> String {
    let mut out = vec![
        "diagnostics report (observation-only: every check below runs a fixed, allowlisted read-only command; nothing here can mutate host state):".to_owned(),
        String::new(),
        "interfaces:".to_owned(),
    ];
    if report.interfaces.is_empty() {
        out.push("  (none observed)".to_owned());
    }
    for iface in &report.interfaces {
        out.push(format!(
            "  - {} up={} mtu={} mac={} ips={:?}",
            iface.name,
            iface.up,
            iface.mtu,
            iface.mac_address.as_deref().unwrap_or("-"),
            iface.ip_addresses
        ));
    }

    out.push(String::new());
    out.push("routes:".to_owned());
    if report.routes.is_empty() {
        out.push("  (none observed)".to_owned());
    }
    for route in &report.routes {
        out.push(format!(
            "  - dest={} gateway={} interface={}",
            route.destination, route.gateway, route.interface
        ));
    }

    out.push(String::new());
    out.push("dns:".to_owned());
    out.push(format!("  method: {}", report.dns.method));
    out.push(format!("  resolvers: {:?}", report.dns.resolvers));
    out.push(format!("  search domains: {:?}", report.dns.search_domains));

    out.push(String::new());
    out.push("listening sockets:".to_owned());
    if report.listening_sockets.is_empty() {
        out.push("  (none observed)".to_owned());
    }
    for socket in &report.listening_sockets {
        out.push(format!(
            "  - {} {}:{} pid={:?}",
            socket.protocol, socket.address, socket.port, socket.pid
        ));
    }

    out.push(String::new());
    out.push("firewall:".to_owned());
    out.push(format!("  backend: {:?}", report.firewall.backend));
    out.push(format!(
        "  active={} queried={} rule_count={:?}",
        report.firewall.active, report.firewall.queried, report.firewall.rule_count
    ));
    out.push(format!("  detail: {}", report.firewall.detail));

    out.push(String::new());
    out.push("rustynet service:".to_owned());
    out.push(format!(
        "  running={} status=\"{}\"",
        report.service.running, report.service.status_message
    ));

    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ------------------------------------------------------------------
    // Allowlist / by-construction observation-only enforcement
    // ------------------------------------------------------------------

    #[test]
    fn every_allowlist_row_is_recognized() {
        for (program, args) in READ_ONLY_COMMANDS {
            assert!(
                is_allowlisted(program, args),
                "row ({program}, {args:?}) should recognize itself"
            );
        }
    }

    #[test]
    fn mutating_verbs_are_rejected() {
        let mutating = [
            ("nft", vec!["-f", "/tmp/ruleset"]),
            (
                "nft",
                vec!["add", "rule", "inet", "filter", "input", "accept"],
            ),
            ("iptables", vec!["-A", "INPUT", "-j", "DROP"]),
            ("iptables", vec!["-F"]),
            ("systemctl", vec!["restart", "rustynetd"]),
            ("systemctl", vec!["stop", "rustynetd"]),
            ("pfctl", vec!["-f", "/etc/pf.conf"]),
            ("pfctl", vec!["-d"]),
            ("launchctl", vec!["unload", "com.rustynet.daemon"]),
            ("launchctl", vec!["kickstart", "com.rustynet.daemon"]),
            ("sc", vec!["stop", "RustyNet"]),
            ("sc", vec!["delete", "RustyNet"]),
            (
                "netsh",
                vec!["advfirewall", "set", "allprofiles", "state", "off"],
            ),
            ("ip", vec!["route", "add", "default", "via", "1.2.3.4"]),
        ];
        for (program, args) in mutating {
            assert!(
                !is_allowlisted(program, &args),
                "({program}, {args:?}) must NOT be allowlisted"
            );
        }
    }

    #[test]
    fn run_read_only_rejects_before_spawning_anything() {
        // A command that is not on the allowlist must come back rejected
        // even though the binary genuinely exists on the test host — proof
        // that the gate runs before any spawn is attempted, not that the
        // binary happened to be absent.
        let outcome = run_read_only(
            &SystemCommandRunner,
            "echo",
            &["hello"],
            DEFAULT_COMMAND_TIMEOUT,
        );
        assert_eq!(outcome, CommandOutcome::RejectedNotAllowlisted);
    }

    // ------------------------------------------------------------------
    // Bounded execution
    // ------------------------------------------------------------------

    #[test]
    #[cfg(unix)]
    fn spawn_bounded_kills_a_hung_process_within_the_timeout() {
        let start = Instant::now();
        // `sleep 5` deliberately outlives the 200ms bound below; a correct
        // implementation returns `TimedOut` in well under 5s.
        let outcome = spawn_bounded("sleep", &["5"], Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert_eq!(outcome, CommandOutcome::TimedOut);
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded execution should return promptly, took {elapsed:?}"
        );
    }

    #[test]
    fn spawn_bounded_reports_unavailable_for_a_nonexistent_program() {
        let outcome = spawn_bounded(
            "rustynet-diagnostics-test-nonexistent-binary",
            &[],
            DEFAULT_COMMAND_TIMEOUT,
        );
        assert_eq!(outcome, CommandOutcome::Unavailable);
    }

    #[test]
    #[cfg(unix)]
    fn spawn_bounded_captures_stdout_of_a_fast_command() {
        let outcome = spawn_bounded("echo", &["diagnostics-ok"], DEFAULT_COMMAND_TIMEOUT);
        match outcome {
            CommandOutcome::Completed {
                stdout, success, ..
            } => {
                assert!(success);
                assert_eq!(stdout.trim(), "diagnostics-ok");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Recording fake: capture-seam for "no mutation" + fail-safe tests
    // ------------------------------------------------------------------

    struct RecordingRunner {
        responses: HashMap<(String, Vec<String>), CommandOutcome>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn with_response(mut self, program: &str, args: &[&str], outcome: CommandOutcome) -> Self {
            self.responses.insert(
                (
                    program.to_owned(),
                    args.iter().map(|s| s.to_string()).collect(),
                ),
                outcome,
            );
            self
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> CommandOutcome {
            let key = (
                program.to_owned(),
                args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            );
            self.calls.borrow_mut().push(key.clone());
            self.responses
                .get(&key)
                .cloned()
                .unwrap_or(CommandOutcome::Unavailable)
        }
    }

    /// The seam-based "no mutation" proof required by the PKG-G contract:
    /// build a full report through a recording fake, then assert every
    /// invocation it captured is one of the allowlisted read-only rows.
    #[test]
    fn observing_never_issues_a_mutating_command() {
        let runner = RecordingRunner::new();
        let report = observe_with(&runner);

        // Sanity: the seam was actually exercised (a no-op stub that never
        // called `run` would trivially "pass" the assertion below).
        let invocations = runner.invocations();
        assert!(
            !invocations.is_empty(),
            "observe_with should have issued at least one command"
        );

        for (program, args) in &invocations {
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert!(
                is_allowlisted(program, &arg_refs),
                "observe_with issued a non-allowlisted command: {program} {arg_refs:?}"
            );
        }

        // The report itself must still be well-formed even though every
        // call above resolved to `Unavailable` (no fixtures were
        // registered) — the fail-safe requirement, exercised end to end.
        assert!(!report.service.running);
        assert!(!report.firewall.queried);
    }

    /// Every field must degrade to a safe default (never panic) when every
    /// underlying tool is missing/denied/timed out — the orchestration
    /// analog of the per-parser malformed-input tests below.
    #[test]
    fn observing_with_every_tool_unavailable_is_fail_safe() {
        let runner = RecordingRunner::new(); // no fixtures => Unavailable for all
        let report = observe_with(&runner);

        assert!(report.interfaces.is_empty());
        assert!(report.routes.is_empty());
        assert!(report.dns.resolvers.is_empty());
        assert!(report.listening_sockets.is_empty());
        assert!(!report.firewall.active);
        assert!(!report.firewall.queried);
        assert!(!report.service.running);
    }

    /// End-to-end (seam-level, not just parser-level) proof that a
    /// canned real-shaped tool output flows all the way through
    /// `observe_with` into the typed report — one variant per OS since
    /// each `observe_firewall` only ever calls its own OS's command.
    #[test]
    #[cfg(target_os = "linux")]
    fn observing_reflects_a_canned_active_firewall_response() {
        let runner = RecordingRunner::new().with_response(
            "nft",
            &["list", "ruleset"],
            CommandOutcome::Completed {
                stdout: "table inet filter {\n\tchain input {\n\t}\n}\n".to_owned(),
                stderr: String::new(),
                success: true,
            },
        );
        let report = observe_with(&runner);
        assert!(report.firewall.active);
        assert!(report.firewall.queried);
        assert_eq!(report.firewall.backend, FirewallBackend::Nftables);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn observing_reflects_a_canned_active_firewall_response() {
        let runner = RecordingRunner::new().with_response(
            "pfctl",
            &["-s", "info"],
            CommandOutcome::Completed {
                stdout: "Status: Enabled for 0 days 00:00:01\n".to_owned(),
                stderr: String::new(),
                success: true,
            },
        );
        let report = observe_with(&runner);
        assert!(report.firewall.active);
        assert!(report.firewall.queried);
        assert_eq!(report.firewall.backend, FirewallBackend::PacketFilter);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn observing_reflects_a_canned_active_firewall_response() {
        let runner = RecordingRunner::new().with_response(
            "netsh",
            &["advfirewall", "show", "allprofiles", "state"],
            CommandOutcome::Completed {
                stdout: "State ON\nState ON\nState ON\n".to_owned(),
                stderr: String::new(),
                success: true,
            },
        );
        let report = observe_with(&runner);
        assert!(report.firewall.active);
        assert!(report.firewall.queried);
        assert_eq!(report.firewall.backend, FirewallBackend::WindowsFirewall);
    }

    // ------------------------------------------------------------------
    // Interfaces
    // ------------------------------------------------------------------

    #[test]
    fn sysfs_interfaces_parses_a_representative_tree() {
        let root = std::env::temp_dir().join(format!(
            "rustynet-sysinfo-diag-test-{}-{}",
            std::process::id(),
            "sysfs_interfaces_parses_a_representative_tree"
        ));
        let wg0 = root.join("wg0");
        std::fs::create_dir_all(&wg0).expect("create fixture dir");
        std::fs::write(wg0.join("operstate"), "up\n").expect("write operstate");
        std::fs::write(wg0.join("address"), "aa:bb:cc:dd:ee:ff\n").expect("write address");
        std::fs::write(wg0.join("mtu"), "1420\n").expect("write mtu");

        let ifaces = interface_details_from_sysfs_root(&root);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "wg0");
        assert!(ifaces[0].up);
        assert_eq!(ifaces[0].mtu, 1420);
        assert_eq!(ifaces[0].mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));

        std::fs::remove_dir_all(&root).expect("cleanup fixture dir");
    }

    #[test]
    fn sysfs_interfaces_missing_root_is_fail_safe() {
        let missing = std::env::temp_dir().join("rustynet-sysinfo-diag-test-does-not-exist-xyz");
        assert_eq!(interface_details_from_sysfs_root(&missing), Vec::new());
    }

    #[test]
    fn sysfs_interfaces_malformed_files_degrade_safely() {
        let root = std::env::temp_dir().join(format!(
            "rustynet-sysinfo-diag-test-{}-{}",
            std::process::id(),
            "sysfs_interfaces_malformed_files_degrade_safely"
        ));
        let eth0 = root.join("eth0");
        std::fs::create_dir_all(&eth0).expect("create fixture dir");
        std::fs::write(eth0.join("mtu"), "not-a-number\n").expect("write garbage mtu");
        // No operstate / address file at all.

        let ifaces = interface_details_from_sysfs_root(&root);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(
            ifaces[0].mtu, 0,
            "unparseable mtu degrades to 0, not a panic"
        );
        assert!(!ifaces[0].up, "missing operstate degrades to down");
        assert_eq!(ifaces[0].mac_address, None);

        std::fs::remove_dir_all(&root).expect("cleanup fixture dir");
    }

    #[test]
    fn ifconfig_interfaces_parses_representative_macos_output() {
        let sample = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=400<CHANNEL_IO>
\tether ac:de:48:00:11:22
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
utun3: flags=80d1<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST> mtu 1280
";
        let ifaces = parse_ifconfig_interface_details(sample);
        assert_eq!(ifaces.len(), 3);
        assert_eq!(ifaces[0].name, "en0");
        assert!(ifaces[0].up);
        assert_eq!(ifaces[0].mtu, 1500);
        assert_eq!(ifaces[0].mac_address.as_deref(), Some("ac:de:48:00:11:22"));
        assert_eq!(ifaces[0].ip_addresses, vec!["192.168.1.23".to_owned()]);
        assert_eq!(ifaces[1].name, "lo0");
        assert_eq!(ifaces[1].mtu, 16384);
        assert_eq!(ifaces[2].name, "utun3");
        assert_eq!(ifaces[2].mtu, 1280);
        assert_eq!(ifaces[2].mac_address, None);
    }

    #[test]
    fn ifconfig_interfaces_malformed_input_is_fail_safe() {
        assert_eq!(parse_ifconfig_interface_details(""), Vec::new());
        assert_eq!(
            parse_ifconfig_interface_details("\t\tgarbage indented\n"),
            Vec::new()
        );
        // A header line with no recognizable mtu/ether/inet body still
        // yields one interface with safe defaults instead of panicking.
        let ifaces = parse_ifconfig_interface_details("en9: flags=0\n");
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].mtu, 0);
        assert_eq!(ifaces[0].mac_address, None);
        assert!(ifaces[0].ip_addresses.is_empty());
    }

    #[test]
    fn netsh_show_interfaces_parses_representative_output() {
        let sample = "\r
Interface List for IPv4:\r
Idx     Met         MTU          State                Name\r
---  ----------  ----------  ------------  ---------------------------\r
  1          50  4294967295  connected     Loopback Pseudo-Interface 1\r
 12          25        1500  connected     Ethernet\r
 17          25        1500  disconnected  Wi-Fi Adapter\r
";
        let ifaces = parse_netsh_show_interfaces(sample);
        assert_eq!(ifaces.len(), 3);
        assert_eq!(ifaces[0].name, "Loopback Pseudo-Interface 1");
        assert_eq!(ifaces[0].mtu, u32::MAX);
        assert!(ifaces[0].up);
        assert_eq!(ifaces[1].name, "Ethernet");
        assert_eq!(ifaces[1].mtu, 1500);
        assert!(ifaces[1].up);
        assert_eq!(ifaces[2].name, "Wi-Fi Adapter");
        assert!(!ifaces[2].up);
    }

    #[test]
    fn netsh_show_interfaces_malformed_input_is_fail_safe() {
        assert_eq!(parse_netsh_show_interfaces(""), Vec::new());
        assert_eq!(
            parse_netsh_show_interfaces("Idx Met MTU State Name\n---\n"),
            Vec::new()
        );
        // A too-short row (no name column) is dropped, not misparsed.
        assert_eq!(
            parse_netsh_show_interfaces("1 50 1500 connected\n"),
            Vec::new()
        );
    }

    // ------------------------------------------------------------------
    // Routes
    // ------------------------------------------------------------------

    #[test]
    fn netstat_rn_routes_parses_representative_macos_output() {
        // Captured shape from real macOS 15 `netstat -rn` output: 4
        // header lines, then rows of 4 fields (5 when an expire time or
        // trailing flag is present).
        let sample = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.18.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
192.168.18.1       10:3c:59:20:b3:3a  UHLWIir               en0   1180
192.168.18.7/32    link#14            UCS                   en0
";
        let routes = parse_netstat_rn_routes(sample);
        assert_eq!(routes.len(), 4);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].gateway, "192.168.18.1");
        assert_eq!(routes[0].interface, "en0");
        assert_eq!(routes[2].destination, "192.168.18.1");
        assert_eq!(routes[2].interface, "en0");
        assert_eq!(routes[3].destination, "192.168.18.7/32");
        assert_eq!(routes[3].gateway, "link#14");
    }

    #[test]
    fn netstat_rn_routes_malformed_input_is_fail_safe() {
        assert_eq!(parse_netstat_rn_routes(""), Vec::new());
        assert_eq!(
            parse_netstat_rn_routes("one\ntwo\nthree\nfour\n"),
            Vec::new()
        );
        assert_eq!(parse_netstat_rn_routes("a\nb\nc\nd\nshort\n"), Vec::new());
    }

    // ------------------------------------------------------------------
    // Listening sockets (macOS `netstat -an`)
    // ------------------------------------------------------------------

    #[test]
    fn netstat_an_listening_macos_parses_representative_output() {
        // Captured shape from real macOS 15 `netstat -an` output: state is
        // field 5 (not embedded in the address field), local address is
        // `ip.port` in field 3.
        let sample = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.18.7.61517     3.173.21.63.443        ESTABLISHED
tcp4       0      0  127.0.0.1.5901         *.*                    LISTEN
tcp6       0      0  *.53                   *.*                    LISTEN
tcp4       0      0  *.53                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN
";
        let sockets = parse_netstat_an_listening_macos(sample);
        assert_eq!(sockets.len(), 4);
        assert_eq!(sockets[0].address, "127.0.0.1");
        assert_eq!(sockets[0].port, 5901);
        assert_eq!(sockets[0].protocol, "tcp4");
        assert_eq!(sockets[2].address, "*");
        assert_eq!(sockets[2].port, 53);
    }

    #[test]
    fn netstat_an_listening_macos_malformed_input_is_fail_safe() {
        assert_eq!(parse_netstat_an_listening_macos(""), Vec::new());
        assert_eq!(
            parse_netstat_an_listening_macos("just a header\n"),
            Vec::new()
        );
        // An ESTABLISHED-only line (no LISTEN state) contributes nothing.
        assert_eq!(
            parse_netstat_an_listening_macos(
                "header\ntcp4 0 0 1.2.3.4.80 5.6.7.8.443 ESTABLISHED\n"
            ),
            Vec::new()
        );
        // A row with too few fields (no state column at all) is dropped,
        // not misparsed.
        assert_eq!(
            parse_netstat_an_listening_macos("header\ntcp4 0 0 1.2.3.4.80\n"),
            Vec::new()
        );
        // A LISTEN row whose local-address field has no `.` separator
        // degrades safely (skipped rather than panicking on an
        // out-of-range index).
        assert_eq!(
            parse_netstat_an_listening_macos("header\ntcp4 0 0 noport foreign LISTEN\n"),
            Vec::new()
        );
    }

    #[test]
    fn route_print_routes_parses_representative_windows_output() {
        let sample = "\
===========================================================================
Interface List
 12...00 11 22 33 44 55 ......Ethernet
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
        192.168.1.0    255.255.255.0         On-link    192.168.1.50    281
===========================================================================
";
        let routes = parse_route_print_routes(sample);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "0.0.0.0");
        assert_eq!(routes[0].gateway, "192.168.1.1");
        assert_eq!(routes[0].interface, "192.168.1.50");
    }

    #[test]
    fn route_print_routes_malformed_input_is_fail_safe() {
        assert_eq!(parse_route_print_routes(""), Vec::new());
        assert_eq!(parse_route_print_routes("x\ny\nz\n"), Vec::new());
    }

    // ------------------------------------------------------------------
    // DNS
    // ------------------------------------------------------------------

    #[test]
    fn resolv_conf_parses_representative_content() {
        let sample = "\
# generated
nameserver 192.168.1.1
nameserver 1.1.1.1
search lan example.com
";
        let dns = parse_resolv_conf(sample);
        assert_eq!(dns.resolvers, vec!["192.168.1.1", "1.1.1.1"]);
        assert_eq!(dns.search_domains, vec!["lan", "example.com"]);
        assert_eq!(dns.method, "resolv.conf");
    }

    #[test]
    fn resolv_conf_malformed_and_empty_is_fail_safe() {
        let empty = parse_resolv_conf("");
        assert!(empty.resolvers.is_empty());
        assert!(empty.search_domains.is_empty());

        let garbage = parse_resolv_conf("not a resolv.conf line\n;; comment\n# also comment\n");
        assert!(garbage.resolvers.is_empty());
        assert!(garbage.search_domains.is_empty());

        // Duplicate nameserver lines dedupe.
        let dup = parse_resolv_conf("nameserver 1.1.1.1\nnameserver 1.1.1.1\n");
        assert_eq!(dup.resolvers, vec!["1.1.1.1"]);
    }

    #[test]
    fn scutil_dns_parses_representative_output() {
        let sample = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
  if_index : 5 (en0)

resolver #2
  nameserver[0] : 192.168.1.1
  flags    : Request A records
";
        let dns = parse_scutil_dns(sample);
        assert_eq!(dns.resolvers, vec!["192.168.1.1", "1.1.1.1"]);
        assert_eq!(dns.search_domains, vec!["lan"]);
        assert_eq!(dns.method, "scutil --dns");
    }

    #[test]
    fn scutil_dns_malformed_input_is_fail_safe() {
        let empty = parse_scutil_dns("");
        assert!(empty.resolvers.is_empty());
        let garbage = parse_scutil_dns("DNS configuration\n(no resolvers found)\n");
        assert!(garbage.resolvers.is_empty());
    }

    #[test]
    fn netsh_dns_parses_representative_output() {
        let sample = "\
Configuration for interface \"Ethernet\"
    Statically Configured DNS Servers:    192.168.1.1
                                           1.1.1.1
    Register with which suffix:           Primary Only

Configuration for interface \"Loopback Pseudo-Interface 1\"
    DNS servers configured through DHCP:  None
";
        let dns = parse_netsh_dns(sample);
        assert_eq!(dns.resolvers, vec!["192.168.1.1", "1.1.1.1"]);
        assert!(dns.search_domains.is_empty());
        assert_eq!(dns.method, "netsh interface ip show dns");
    }

    #[test]
    fn netsh_dns_malformed_input_is_fail_safe() {
        assert!(parse_netsh_dns("").resolvers.is_empty());
        assert!(
            parse_netsh_dns("nothing relevant here\n")
                .resolvers
                .is_empty()
        );
        // "None" is not IP-shaped, so it must not be captured as a resolver.
        assert!(
            parse_netsh_dns("DNS servers configured through DHCP:  None\n")
                .resolvers
                .is_empty()
        );
    }

    #[test]
    fn looks_like_ip_token_accepts_v4_and_v6_rejects_prose() {
        assert!(looks_like_ip_token("192.168.1.1"));
        assert!(looks_like_ip_token("fe80::1"));
        assert!(!looks_like_ip_token("None"));
        assert!(!looks_like_ip_token(""));
        assert!(!looks_like_ip_token("Primary"));
    }

    // ------------------------------------------------------------------
    // Firewall
    // ------------------------------------------------------------------

    #[test]
    fn nft_ruleset_status_parses_representative_output() {
        let sample = "\
table inet filter {
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t}
\tchain forward {
\t\ttype filter hook forward priority 0; policy drop;
\t}
}
";
        let status = parse_nft_ruleset_status(sample);
        assert_eq!(status.backend, FirewallBackend::Nftables);
        assert!(status.active);
        assert!(status.queried);
        assert_eq!(status.rule_count, Some(2));
    }

    #[test]
    fn nft_ruleset_status_empty_ruleset_is_inactive_but_queried() {
        let status = parse_nft_ruleset_status("");
        assert_eq!(status.backend, FirewallBackend::Nftables);
        assert!(!status.active);
        assert!(
            status.queried,
            "an empty-but-successful query was still made"
        );
        assert_eq!(status.rule_count, Some(0));
    }

    #[test]
    fn iptables_list_status_parses_representative_output() {
        let sample = "\
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
";
        let status = parse_iptables_list_status(sample);
        assert_eq!(status.backend, FirewallBackend::Iptables);
        assert!(status.active);
        assert_eq!(status.rule_count, Some(3));
    }

    #[test]
    fn iptables_list_status_malformed_input_is_fail_safe() {
        let status = parse_iptables_list_status("");
        assert!(!status.active);
        assert_eq!(status.rule_count, Some(0));
        assert!(status.queried);
    }

    #[test]
    fn pfctl_info_status_parses_enabled_and_disabled() {
        let enabled = parse_pfctl_info_status("Status: Enabled for 3 days 00:12:34\n");
        assert!(enabled.active);
        assert!(enabled.queried);

        let disabled = parse_pfctl_info_status("Status: Disabled\n");
        assert!(!disabled.active);
        assert!(disabled.queried);
    }

    #[test]
    fn pfctl_info_status_malformed_input_is_fail_safe() {
        let status = parse_pfctl_info_status("garbage, no status line\n");
        assert!(!status.active);
        assert!(
            !status.queried,
            "no Status line means we couldn't confirm anything"
        );

        let empty = parse_pfctl_info_status("");
        assert!(!empty.queried);
    }

    #[test]
    fn netsh_advfirewall_state_parses_representative_output() {
        let sample = "\
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
";
        let status = parse_netsh_advfirewall_state(sample);
        assert_eq!(status.backend, FirewallBackend::WindowsFirewall);
        assert!(status.active);
        assert!(status.queried);
        assert_eq!(status.rule_count, Some(2));
    }

    #[test]
    fn netsh_advfirewall_state_malformed_input_is_fail_safe() {
        let status = parse_netsh_advfirewall_state("garbage output, no State lines\n");
        assert!(!status.active);
        assert!(!status.queried);

        let empty = parse_netsh_advfirewall_state("");
        assert!(!empty.active);
        assert!(!empty.queried);
    }

    // ------------------------------------------------------------------
    // Rustynet service status
    // ------------------------------------------------------------------

    #[test]
    fn launchctl_list_status_running_vs_not_running() {
        let running = parse_launchctl_list_status(
            "{\n\t\"Label\" = \"com.rustynet.daemon\";\n\t\"PID\" = 4242;\n}\n",
        );
        assert!(running.running);

        let idle = parse_launchctl_list_status("{\n\t\"Label\" = \"com.rustynet.daemon\";\n}\n");
        assert!(!idle.running);
    }

    #[test]
    fn launchctl_list_status_malformed_input_is_fail_safe() {
        let status = parse_launchctl_list_status("");
        assert!(!status.running);
    }

    #[test]
    fn sc_query_status_parses_running_and_stopped() {
        let running = parse_sc_query_status(
            "SERVICE_NAME: RustyNet\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n",
        );
        assert!(running.running);
        assert_eq!(running.status_message, "RUNNING");

        let stopped = parse_sc_query_status("        STATE              : 1  STOPPED\n");
        assert!(!stopped.running);
        assert_eq!(stopped.status_message, "STOPPED");
    }

    #[test]
    fn sc_query_status_malformed_input_is_fail_safe() {
        let status = parse_sc_query_status("no state line here\n");
        assert!(!status.running);

        let empty = parse_sc_query_status("");
        assert!(!empty.running);
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    #[test]
    fn render_report_includes_every_section_and_never_panics_on_empty_report() {
        let report = DiagnosticsReport {
            interfaces: Vec::new(),
            routes: Vec::new(),
            dns: DnsResolverInfo {
                resolvers: Vec::new(),
                search_domains: Vec::new(),
                method: "test".to_owned(),
            },
            listening_sockets: Vec::new(),
            firewall: FirewallStatus {
                backend: FirewallBackend::Unknown,
                active: false,
                rule_count: None,
                queried: false,
                detail: "test".to_owned(),
            },
            service: ServiceStatus {
                running: false,
                status_message: "test".to_owned(),
            },
        };
        let rendered = render_report(&report);
        for heading in [
            "interfaces:",
            "routes:",
            "dns:",
            "listening sockets:",
            "firewall:",
            "rustynet service:",
        ] {
            assert!(rendered.contains(heading), "missing section: {heading}");
        }
    }

    /// Not run in gates (`#[ignore]`): a manual, real-subprocess smoke
    /// check against the actual dev host, useful when hand-verifying a
    /// parser change. Run with `cargo test -p rustynet-sysinfo -- --ignored
    /// --nocapture observe_system_diagnostics_smoke`. Asserts only that it
    /// completes without panicking — the point is to eyeball
    /// `render_report`'s output against the host's real `ifconfig`/
    /// `netstat -rn`/`scutil --dns`, not to pin exact values that would
    /// make the test flaky across hosts.
    #[test]
    #[ignore]
    fn observe_system_diagnostics_smoke() {
        let report = observe_system_diagnostics();
        println!("{}", render_report(&report));
    }
}
