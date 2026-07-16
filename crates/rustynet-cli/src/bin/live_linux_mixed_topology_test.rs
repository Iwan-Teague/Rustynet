#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]
// Track B Phase 28 transition: still calls the deprecated
// `capture_root` shim. Phase 29 rewrites on the new
// `RemoteShellHost` trait. Allow until then so `-D warnings` passes.
#![allow(deprecated)]

//! Track B Phases 12 + 13 — mixed-OS topology integration validator.
//!
//! Proves Linux + macOS + Windows nodes share one signed membership
//! view AND have actually exchanged recent WireGuard handshakes with
//! each other — the convergence + datapath check that closes Track B.
//!
//! Track B Phases 4-11 land per-host validators (exit-handoff /
//! relay-service-lifecycle / anchor) that prove each platform
//! correctly runs its role in isolation. Phase 12 added the
//! membership-convergence check using `rustynet anchor list`; Phase
//! 13 strengthened that with two upgrades:
//!
//!   1. switched the membership probe from `rustynet anchor list`
//!      (anchor-only) to `rustynet membership status`
//!      (all active members regardless of capability) so non-anchor
//!      hosts can appear in the visibility check;
//!   2. added a datapath probe via `rustynet status` that pulls
//!      `path_live_proven`, `path_live_peer_count`, and
//!      `path_latest_live_handshake_unix`, then asserts every host
//!      has a proven live datapath with at least N-1 live peers and
//!      a handshake within the configurable freshness window
//!      (default 600 s).
//!
//! Substages:
//!   1. capture_membership_status_each_host — drive
//!      `rustynet membership status` on each of the three nodes
//!      (capture_root + POSIX shell on Linux/macOS, PowerShell over
//!      Administrator SSH on Windows).
//!   2. capture_daemon_status_each_host — drive `rustynet status` via
//!      the cross-platform `capture_daemon_status_for_platform`
//!      helper from `live_lab_bin_support`.
//!   3. verify_mutual_membership_visibility — every host must list
//!      every OTHER host's node_id in its membership snapshot.
//!   4. verify_datapath_freshness — every host must have
//!      `path_live_proven=true`, ≥ N-1 live peers, and a handshake
//!      within `--handshake-freshness-secs` (default 600).
//!   5. emit_topology_report — canonical envelope (phase, mode,
//!      evidence_mode, captured_at, captured_at_unix, git_commit,
//!      source_artifacts, status) with a per-host coverage matrix
//!      including the datapath snapshot.
//!
//! The validator fails closed when any host cannot be reached, any
//! host's membership snapshot is missing a peer it should observe,
//! any host's datapath is not proven live, or any capture errors
//! out. There is no PASS without ALL hosts present in ALL views
//! AND every host carrying a fresh handshake to at least N-1 peers.

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    REMOTE_RUSTYNET_BIN, capture_daemon_status_for_platform, capture_remote_stdout, capture_root,
    create_workspace, ensure_pinned_known_hosts_file, ensure_safe_token, git_head_commit,
    load_home_known_hosts_path, repo_root, require_command, seed_known_hosts,
    verify_passwordless_sudo, verify_sudo, verify_windows_admin, write_file,
};
use serde::Serialize;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;

    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;
    let workspace = create_workspace("mixed-topology")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let hosts = config.hosts();
    // Preflight every host with the platform-appropriate verifier.
    // Fail-closed at this step prevents a partial capture that
    // would silently misclassify mutual visibility.
    for host in &hosts {
        match host.platform {
            HostPlatform::Linux => {
                verify_sudo(&config.ssh_identity_file, &work_known_hosts, &host.target)
                    .map_err(|err| format!("linux preflight failed for {}: {err}", host.label))?;
            }
            HostPlatform::Macos => {
                verify_passwordless_sudo(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    &host.target,
                )
                .map_err(|err| format!("macos preflight failed for {}: {err}", host.label))?;
            }
            HostPlatform::Windows => {
                verify_windows_admin(&config.ssh_identity_file, &work_known_hosts, &host.target)
                    .map_err(|err| format!("windows preflight failed for {}: {err}", host.label))?;
            }
        }
    }

    // Capture `rustynet anchor list` AND `rustynet status` on each
    // host. The anchor list proves signed membership convergence;
    // the status line proves the daemon has actually exchanged a
    // recent WireGuard handshake with at least N-1 peers (where N
    // is the topology size). Membership convergence without
    // datapath traffic would still pass the older visibility check
    // — Phase 13 adds the handshake-freshness assertion to close
    // that gap.
    let now_unix = unix_now_secs();
    let mut views: Vec<HostView> = Vec::with_capacity(hosts.len());
    for host in &hosts {
        let membership_status = capture_membership_status(
            &config.ssh_identity_file,
            &work_known_hosts,
            host.target.as_str(),
            host.platform,
        )
        .map_err(|err| {
            format!(
                "membership status capture failed for {} ({}): {err}",
                host.label,
                host.platform.as_str()
            )
        })?;
        let observed = parse_active_node_ids(membership_status.as_str());
        let status_line = capture_daemon_status_for_platform(
            &config.ssh_identity_file,
            &work_known_hosts,
            host.target.as_str(),
            host.platform.as_str(),
        )
        .map_err(|err| {
            format!(
                "daemon status capture failed for {} ({}): {err}",
                host.label,
                host.platform.as_str()
            )
        })?;
        let datapath = parse_datapath_status(status_line.as_str());
        views.push(HostView {
            label: host.label.clone(),
            target: host.target.clone(),
            platform: host.platform,
            node_id: host.node_id.clone(),
            observed,
            raw_membership_excerpt: first_lines(membership_status.as_str(), 4),
            datapath,
            raw_status_excerpt: first_lines(status_line.as_str(), 4),
        });
    }

    // Verify mutual visibility — every host must see every OTHER
    // host's node_id in its membership snapshot.
    let mut failures: Vec<String> = Vec::new();
    for view in &views {
        for other in &hosts {
            if other.node_id == view.node_id {
                continue;
            }
            if !view.observed.iter().any(|node| node == &other.node_id) {
                failures.push(format!(
                    "{} ({}) does NOT observe peer {} ({}) in its membership snapshot",
                    view.label,
                    view.platform.as_str(),
                    other.label,
                    other.node_id,
                ));
            }
        }
    }

    // Verify datapath freshness — each host must have
    // `path_live_proven=true`, at least N-1 live peers, and a
    // handshake within the freshness window. Configurable via
    // --handshake-freshness-secs (default 600s); 0 disables.
    if config.handshake_freshness_secs > 0 {
        let required_live_peers = (hosts.len() as u32).saturating_sub(1);
        for view in &views {
            if !view.datapath.path_live_proven {
                failures.push(format!(
                    "{} ({}) datapath NOT proven live (path_live_proven=false)",
                    view.label,
                    view.platform.as_str(),
                ));
            }
            if view.datapath.path_live_peer_count < required_live_peers {
                failures.push(format!(
                    "{} ({}) has only {} live peer(s); expected at least {} for {}-host topology",
                    view.label,
                    view.platform.as_str(),
                    view.datapath.path_live_peer_count,
                    required_live_peers,
                    hosts.len(),
                ));
            }
            match view.datapath.path_latest_live_handshake_unix {
                Some(handshake_ts) => {
                    let age = now_unix.saturating_sub(handshake_ts as i64);
                    if age > config.handshake_freshness_secs as i64 {
                        failures.push(format!(
                            "{} ({}) handshake stale ({}s old, freshness window {}s)",
                            view.label,
                            view.platform.as_str(),
                            age,
                            config.handshake_freshness_secs,
                        ));
                    }
                }
                None => {
                    failures.push(format!(
                        "{} ({}) has NO observed handshake (path_latest_live_handshake_unix missing)",
                        view.label,
                        view.platform.as_str(),
                    ));
                }
            }
        }
    }

    let status = if failures.is_empty() { "pass" } else { "fail" };
    let detail = if failures.is_empty() {
        format!(
            "all {} hosts mutually visible in signed membership",
            hosts.len()
        )
    } else {
        failures.join("; ")
    };

    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        repo_root()?.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        repo_root()?.join(&config.report_path)
    };
    let root = repo_root()?;
    let git_commit = config
        .git_commit
        .clone()
        .unwrap_or_else(|| git_head_commit(&root).unwrap_or_else(|_| "unknown".to_owned()));
    let report = MixedTopologyReport {
        schema_version: 1,
        phase: "phase10",
        mode: "live_mixed_topology_visibility",
        evidence_mode: "measured",
        status,
        captured_at: utc_now_string(),
        captured_at_unix: unix_now_secs() as u64,
        git_commit,
        host_count: hosts.len() as u32,
        views,
        source_artifacts: vec![log_path.display().to_string()],
        detail: detail.clone(),
    };
    let mut body = serde_json::to_string(&report)
        .map_err(|err| format!("serialize mixed-topology report failed: {err}"))?;
    body.push('\n');
    write_file(&report_path, body.as_str())?;
    let log_body = format!("[mixed-topology] status={status} detail={detail}\n");
    write_file(&log_path, log_body.as_str())?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "mixed-OS topology mutual visibility failed: {}",
            failures.join("; ")
        ))
    }
}

// ─── platform enum + per-host config ──────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum HostPlatform {
    Linux,
    Macos,
    Windows,
}

impl HostPlatform {
    // Exercised by `host_platform_parse_accepts_canonical_words`.
    // Per-host `--<platform>-host` flags carry the platform
    // implicitly (the three CLI flags are fixed to linux / macos /
    // windows), so this parser is not called from `Config::parse`
    // today — it is kept so a future CLI surface that wires a
    // free-form `--platform <p>` arg has a single canonical
    // parser, and so the canonical-spelling regression test
    // (`host_platform_parse_accepts_canonical_words`) protects
    // the cross-bin contract.
    #[cfg_attr(not(test), allow(dead_code))]
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux" => Ok(Self::Linux),
            "macos" | "darwin" => Ok(Self::Macos),
            "windows" | "win32" => Ok(Self::Windows),
            other => Err(format!(
                "unsupported platform {other:?}; expected linux, macos, or windows"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

#[derive(Debug, Clone)]
struct HostEntry {
    label: String,
    target: String,
    node_id: String,
    platform: HostPlatform,
}

#[derive(Debug, Serialize)]
struct HostView {
    label: String,
    target: String,
    platform: HostPlatform,
    node_id: String,
    observed: Vec<String>,
    raw_membership_excerpt: String,
    datapath: DatapathStatus,
    raw_status_excerpt: String,
}

/// Subset of the `rustynet status` line that the mixed-topology
/// validator needs to prove datapath traffic between hosts. The
/// full status line is enormous (see `daemon.rs::run`); we only
/// extract three fields here. The serde shape is stable so the
/// orchestrator can read the per-host datapath snapshot from the
/// report without re-parsing the raw line.
#[derive(Debug, Default, Serialize)]
struct DatapathStatus {
    path_live_proven: bool,
    path_live_peer_count: u32,
    path_latest_live_handshake_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
struct MixedTopologyReport {
    schema_version: u32,
    phase: &'static str,
    mode: &'static str,
    evidence_mode: &'static str,
    status: &'static str,
    captured_at: String,
    captured_at_unix: u64,
    git_commit: String,
    host_count: u32,
    views: Vec<HostView>,
    source_artifacts: Vec<String>,
    detail: String,
}

#[derive(Debug)]
struct Config {
    ssh_identity_file: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
    linux_host: String,
    linux_node_id: String,
    macos_host: String,
    macos_node_id: String,
    windows_host: String,
    windows_node_id: String,
    /// Phase 13 — handshake-freshness window (seconds). The
    /// datapath assertion fails if a host's
    /// `path_latest_live_handshake_unix` is older than this many
    /// seconds at capture time. Default 600s; `0` disables the
    /// datapath check entirely (used by smoke tests that only care
    /// about membership convergence).
    handshake_freshness_secs: u64,
    report_path: PathBuf,
    log_path: PathBuf,
    git_commit: Option<String>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            ssh_identity_file: PathBuf::new(),
            pinned_known_hosts_file: None,
            linux_host: "debian@192.168.18.49".to_owned(),
            linux_node_id: "exit-1".to_owned(),
            macos_host: "admin@192.168.18.50".to_owned(),
            macos_node_id: "relay-mac".to_owned(),
            windows_host: "admin@192.168.18.40".to_owned(),
            windows_node_id: "client-win".to_owned(),
            handshake_freshness_secs: 600,
            report_path: PathBuf::from("artifacts/phase10/live_mixed_topology_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_mixed_topology.log"),
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT").ok(),
        };
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?));
                }
                "--linux-host" => config.linux_host = next_value(&mut iter, &arg)?,
                "--linux-node-id" => config.linux_node_id = next_value(&mut iter, &arg)?,
                "--macos-host" => config.macos_host = next_value(&mut iter, &arg)?,
                "--macos-node-id" => config.macos_node_id = next_value(&mut iter, &arg)?,
                "--windows-host" => config.windows_host = next_value(&mut iter, &arg)?,
                "--windows-node-id" => config.windows_node_id = next_value(&mut iter, &arg)?,
                "--handshake-freshness-secs" => {
                    let raw = next_value(&mut iter, &arg)?;
                    config.handshake_freshness_secs = raw.parse::<u64>().map_err(|err| {
                        format!("--handshake-freshness-secs must be a non-negative integer: {err}")
                    })?;
                }
                "--report-path" => {
                    config.report_path = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--log-path" => {
                    config.log_path = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--git-commit" => {
                    config.git_commit = Some(next_value(&mut iter, &arg)?);
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }
        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_mixed_topology_test --ssh-identity-file <path> [options]"
                    .to_owned(),
            );
        }
        for (label, value) in [
            ("linux-host", config.linux_host.as_str()),
            ("linux-node-id", config.linux_node_id.as_str()),
            ("macos-host", config.macos_host.as_str()),
            ("macos-node-id", config.macos_node_id.as_str()),
            ("windows-host", config.windows_host.as_str()),
            ("windows-node-id", config.windows_node_id.as_str()),
        ] {
            ensure_safe_token(label, value)?;
        }
        Ok(config)
    }

    fn hosts(&self) -> Vec<HostEntry> {
        vec![
            HostEntry {
                label: "linux".to_owned(),
                target: self.linux_host.clone(),
                node_id: self.linux_node_id.clone(),
                platform: HostPlatform::Linux,
            },
            HostEntry {
                label: "macos".to_owned(),
                target: self.macos_host.clone(),
                node_id: self.macos_node_id.clone(),
                platform: HostPlatform::Macos,
            },
            HostEntry {
                label: "windows".to_owned(),
                target: self.windows_host.clone(),
                node_id: self.windows_node_id.clone(),
                platform: HostPlatform::Windows,
            },
        ]
    }
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    println!(
        "usage: live_linux_mixed_topology_test --ssh-identity-file <path> [options]\n\
         \n\
         Track B Phase 12 — mixed-OS topology mutual-visibility check.\n\
         Captures `rustynet anchor list` on Linux + macOS + Windows\n\
         hosts and asserts every host observes every OTHER host.\n\
         \n\
         options:\n\
         \x20\x20--linux-host <user@host>          Linux SSH target\n\
         \x20\x20--linux-node-id <id>              Linux signed-membership node id\n\
         \x20\x20--macos-host <user@host>          macOS SSH target\n\
         \x20\x20--macos-node-id <id>              macOS signed-membership node id\n\
         \x20\x20--windows-host <user@host>        Windows SSH target\n\
         \x20\x20--windows-node-id <id>            Windows signed-membership node id\n\
         \x20\x20--handshake-freshness-secs <n>   datapath WireGuard handshake freshness window (default 600; 0 disables)\n\
         \x20\x20--known-hosts <path>              pinned SSH known_hosts\n\
         \x20\x20--report-path <path>              JSON report output\n\
         \x20\x20--log-path <path>                 human-readable log output\n\
         \x20\x20--git-commit <sha>                override RUSTYNET_EXPECTED_GIT_COMMIT"
    );
}

// ─── per-platform `rustynet anchor list` capture ──────────────────

/// Capture the canonical `rustynet membership status` line.
/// Phase 12 originally used `rustynet anchor list` here, but
/// Phase 12 reviewer caught that anchor list ONLY emits
/// anchor-capable nodes (see `crates/rustynet-cli/src/main.rs`
/// render_anchor_list) — a client-only Windows node would never
/// appear and the mutual-visibility check would fail by
/// construction. `membership status` instead emits an
/// `active_nodes=<csv>` field that lists every active member
/// regardless of capability — exactly the right surface for
/// proving cross-OS membership convergence.
///
/// POSIX path uses `&&` to short-circuit: if `rustynet` is not on
/// PATH, the second command does not run and the failure is
/// surfaced through capture_root's non-zero exit handling. The
/// previous `;` separator would have run `rustynet membership
/// status` anyway and produced an empty body that the parser
/// would misclassify as "no peers observed".
fn capture_membership_status(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    platform: HostPlatform,
) -> Result<String, String> {
    match platform {
        HostPlatform::Linux | HostPlatform::Macos => {
            let command = &format!(
                "command -v {REMOTE_RUSTYNET_BIN} >/dev/null && {REMOTE_RUSTYNET_BIN} membership status"
            );
            capture_root(identity, known_hosts, host, command)
        }
        HostPlatform::Windows => {
            // `Out-String -Width 32767` so the long membership-status
            // line is not wrapped at terminal width; the parser
            // requires the active_nodes=... CSV to live on a single
            // physical line.
            let command = "powershell -NoProfile -Command \"if (-not (Get-Command rustynet.exe -ErrorAction SilentlyContinue)) { Write-Error 'rustynet.exe not on PATH'; exit 1 }; rustynet.exe membership status | Out-String -Width 32767\"";
            capture_remote_stdout(identity, known_hosts, host, command)
        }
    }
}

/// Parse `rustynet membership status` stdout into the set of
/// active node ids the daemon's signed membership snapshot
/// carries. The canonical format (see
/// `crates/rustynet-cli/src/main.rs::MembershipCommand::Status`)
/// is a single line:
///
/// ```text
/// membership status: network_id=<id> epoch=<n> quorum_threshold=<n> active_nodes=<csv> state_root=<hex>
/// ```
///
/// Extract the `active_nodes=` CSV; tolerate trailing whitespace
/// and additional space-delimited key=value pairs after it.
fn parse_active_node_ids(membership_status: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in membership_status.lines() {
        let trimmed = line.trim();
        let Some(active_idx) = trimmed.find("active_nodes=") else {
            continue;
        };
        let csv = &trimmed[active_idx + "active_nodes=".len()..];
        // The next key=value pair is space-separated, so cut on the
        // first space.
        let csv = csv.split_whitespace().next().unwrap_or("");
        for entry in csv.split(',') {
            let entry = entry.trim();
            if !entry.is_empty() {
                out.push(entry.to_owned());
            }
        }
        break;
    }
    out.sort();
    out.dedup();
    out
}

/// Parse selected datapath fields from the canonical single-line
/// `rustynet status` output. The line is space-separated `key=value`
/// pairs (see `crates/rustynetd/src/daemon.rs::run`); pull the three
/// we care about for cross-OS proof:
///   * path_live_proven=true|false
///   * path_live_peer_count=<u32>
///   * path_latest_live_handshake_unix=<u64|"none"|empty>
///     (the daemon emits the literal string "none" when no peer
///     has ever handshaken; the parser maps "none" / "0" / unparseable
///     values to `None` so the freshness check fails closed on a
///     stale or never-established datapath)
fn parse_datapath_status(status_line: &str) -> DatapathStatus {
    let mut out = DatapathStatus::default();
    let trimmed = status_line.trim();
    for pair in trimmed.split_whitespace() {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "path_live_proven" => {
                out.path_live_proven = value.eq_ignore_ascii_case("true");
            }
            "path_live_peer_count" => {
                out.path_live_peer_count = value.parse::<u32>().unwrap_or(0);
            }
            "path_latest_live_handshake_unix" => {
                out.path_latest_live_handshake_unix = if value.is_empty() {
                    None
                } else {
                    value.parse::<u64>().ok().filter(|ts| *ts > 0)
                };
            }
            _ => {}
        }
    }
    out
}

fn first_lines(text: &str, n: usize) -> String {
    text.lines().take(n).collect::<Vec<_>>().join("\n")
}

fn validate_identity(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing ssh identity file: {}", path.display()));
    }
    if path.is_symlink() {
        return Err(format!(
            "ssh identity file must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn utc_now_string() -> String {
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Config, HostPlatform};

    fn base_args() -> Vec<String> {
        vec!["--ssh-identity-file".to_owned(), "/tmp/id".to_owned()]
    }

    #[test]
    fn config_parse_defaults_to_three_hosts() {
        let cfg = Config::parse(base_args()).expect("default parse");
        let hosts = cfg.hosts();
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].platform, HostPlatform::Linux);
        assert_eq!(hosts[1].platform, HostPlatform::Macos);
        assert_eq!(hosts[2].platform, HostPlatform::Windows);
        // Each host has a distinct node id baked in by default so a
        // mis-configured run is not confused with a real run.
        let mut ids: Vec<&str> = hosts.iter().map(|h| h.node_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["client-win", "exit-1", "relay-mac"]);
    }

    #[test]
    fn config_parse_rejects_unsafe_token_in_host() {
        let mut args = base_args();
        args.push("--macos-host".to_owned());
        args.push("admin@host;rm -rf /".to_owned());
        let err = Config::parse(args).expect_err("shell metacharacters must fail closed");
        assert!(err.contains("unsupported characters"));
    }

    #[test]
    fn config_parse_requires_ssh_identity_file() {
        let err = Config::parse(Vec::new()).expect_err("missing identity must fail");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn config_parse_rejects_unknown_argument_fail_closed() {
        let mut args = base_args();
        args.push("--bogus-flag".to_owned());
        let err = Config::parse(args).expect_err("unknown flag must fail closed");
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn host_platform_parse_accepts_canonical_words() {
        assert_eq!(HostPlatform::parse("linux").unwrap(), HostPlatform::Linux);
        assert_eq!(HostPlatform::parse("darwin").unwrap(), HostPlatform::Macos);
        assert_eq!(HostPlatform::parse("macos").unwrap(), HostPlatform::Macos);
        assert_eq!(
            HostPlatform::parse("windows").unwrap(),
            HostPlatform::Windows
        );
        assert_eq!(HostPlatform::parse("win32").unwrap(), HostPlatform::Windows);
        assert!(HostPlatform::parse("aix").is_err());
    }

    #[test]
    fn parse_active_node_ids_extracts_csv_from_membership_status_line() {
        // Canonical format from
        // `crates/rustynet-cli/src/main.rs::MembershipCommand::Status`:
        // single line with space-separated key=value pairs. The
        // `active_nodes=` value is a CSV that lists every active
        // member — anchor capability is NOT required.
        let body = "membership status: network_id=abc epoch=7 quorum_threshold=2 active_nodes=client-win,exit-1,relay-mac state_root=deadbeef\n";
        let observed = super::parse_active_node_ids(body);
        assert_eq!(observed, vec!["client-win", "exit-1", "relay-mac"]);
    }

    #[test]
    fn parse_active_node_ids_returns_empty_when_active_nodes_csv_missing() {
        let body =
            "membership status: network_id=abc epoch=7 quorum_threshold=2 state_root=deadbeef\n";
        let observed = super::parse_active_node_ids(body);
        assert!(observed.is_empty());
    }

    #[test]
    fn parse_active_node_ids_dedupes_repeated_node_id() {
        // Defense-in-depth: if the daemon ever emits a duplicate
        // node id, the observed set must not double-count.
        let body = "membership status: active_nodes=exit-1,exit-1,relay-mac state_root=cafef00d\n";
        let observed = super::parse_active_node_ids(body);
        assert_eq!(observed, vec!["exit-1", "relay-mac"]);
    }

    #[test]
    fn parse_active_node_ids_tolerates_trailing_whitespace_and_extra_keys() {
        let body = "  membership status: active_nodes=alpha,beta extra=ignored  \n";
        let observed = super::parse_active_node_ids(body);
        assert_eq!(observed, vec!["alpha", "beta"]);
    }

    #[test]
    fn parse_datapath_status_extracts_live_proven_count_and_handshake() {
        let line = "node_id=exit-1 path_live_proven=true path_live_peer_count=2 path_latest_live_handshake_unix=1700000000 other=ignore\n";
        let datapath = super::parse_datapath_status(line);
        assert!(datapath.path_live_proven);
        assert_eq!(datapath.path_live_peer_count, 2);
        assert_eq!(datapath.path_latest_live_handshake_unix, Some(1700000000));
    }

    #[test]
    fn parse_datapath_status_treats_zero_handshake_as_missing() {
        // The daemon emits `path_latest_live_handshake_unix=0` when
        // no peer has ever handshaken. Treat zero as missing so the
        // freshness assertion fails closed rather than parse 0 as
        // a recent timestamp.
        let line =
            "path_live_proven=false path_live_peer_count=0 path_latest_live_handshake_unix=0\n";
        let datapath = super::parse_datapath_status(line);
        assert!(!datapath.path_live_proven);
        assert_eq!(datapath.path_live_peer_count, 0);
        assert!(datapath.path_latest_live_handshake_unix.is_none());
    }

    #[test]
    fn parse_datapath_status_handles_missing_fields() {
        let datapath = super::parse_datapath_status("node_id=alone\n");
        assert!(!datapath.path_live_proven);
        assert_eq!(datapath.path_live_peer_count, 0);
        assert!(datapath.path_latest_live_handshake_unix.is_none());
    }

    #[test]
    fn parse_datapath_status_rejects_non_boolean_path_live_proven() {
        // Strict bool — anything other than `true` is `false`.
        let line = "path_live_proven=maybe path_live_peer_count=3\n";
        let datapath = super::parse_datapath_status(line);
        assert!(!datapath.path_live_proven);
        assert_eq!(datapath.path_live_peer_count, 3);
    }

    #[test]
    fn parse_datapath_status_treats_literal_none_as_missing_handshake() {
        // Phase 13 reviewer MEDIUM: the daemon emits the literal
        // string `none` (not empty) when no peer has handshaken.
        // The parser must collapse "none" to `None` so the
        // freshness check fails closed on a never-established
        // datapath rather than parse `none` as a recent timestamp.
        let line =
            "path_live_proven=false path_live_peer_count=0 path_latest_live_handshake_unix=none\n";
        let datapath = super::parse_datapath_status(line);
        assert!(!datapath.path_live_proven);
        assert!(
            datapath.path_latest_live_handshake_unix.is_none(),
            "literal 'none' must parse as missing"
        );
    }

    #[test]
    fn config_parse_freshness_zero_disables_datapath_check() {
        // Phase 13 reviewer HIGH: the freshness=0 disable surface
        // was claimed but never tested. Pin the round-trip so a
        // future change to argument parsing surfaces here.
        let mut args = base_args();
        args.push("--handshake-freshness-secs".to_owned());
        args.push("0".to_owned());
        let cfg = Config::parse(args).expect("freshness 0 must parse");
        assert_eq!(
            cfg.handshake_freshness_secs, 0,
            "freshness=0 is the documented disable surface; must round-trip exactly"
        );
    }

    #[test]
    fn first_lines_caps_output_to_requested_count() {
        let body = (0..50)
            .map(|i| format!("line-{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let excerpt = super::first_lines(body.as_str(), 5);
        assert_eq!(excerpt.lines().count(), 5);
        assert!(excerpt.starts_with("line-0\n"));
    }

    #[test]
    fn mixed_topology_report_round_trips_through_serde() {
        let view = super::HostView {
            label: "linux".to_owned(),
            target: "debian@192.168.18.49 \" inject \n more".to_owned(),
            platform: super::HostPlatform::Linux,
            node_id: "exit-1".to_owned(),
            observed: vec!["relay-mac".to_owned(), "client-win".to_owned()],
            raw_membership_excerpt: "membership status: active_nodes=exit-1,relay-mac,client-win"
                .to_owned(),
            datapath: super::DatapathStatus {
                path_live_proven: true,
                path_live_peer_count: 2,
                path_latest_live_handshake_unix: Some(1700000000),
            },
            raw_status_excerpt: "node_id=exit-1 path_live_proven=true path_live_peer_count=2"
                .to_owned(),
        };
        let report = super::MixedTopologyReport {
            schema_version: 1,
            phase: "phase10",
            mode: "live_mixed_topology_visibility",
            evidence_mode: "measured",
            status: "fail",
            captured_at: "1970-01-01T00:00:00Z".to_owned(),
            captured_at_unix: 100,
            git_commit: "deadbeef".to_owned(),
            host_count: 3,
            views: vec![view],
            source_artifacts: vec!["live-lab/mixed-topology.log".to_owned()],
            detail: "linux does NOT observe peer relay-mac".to_owned(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("round-trip JSON");
        assert_eq!(parsed["mode"], "live_mixed_topology_visibility");
        assert_eq!(parsed["phase"], "phase10");
        assert_eq!(parsed["evidence_mode"], "measured");
        assert_eq!(parsed["status"], "fail");
        assert_eq!(parsed["host_count"], 3);
        assert_eq!(parsed["views"][0]["platform"], "linux");
        assert_eq!(parsed["views"][0]["observed"][0], "relay-mac");
        assert_eq!(parsed["views"][0]["datapath"]["path_live_proven"], true);
        assert_eq!(parsed["views"][0]["datapath"]["path_live_peer_count"], 2);
        assert_eq!(
            parsed["views"][0]["datapath"]["path_latest_live_handshake_unix"],
            1700000000
        );
        assert_eq!(
            parsed["views"][0]["target"], "debian@192.168.18.49 \" inject \n more",
            "embedded quote/newline must survive serde escaping"
        );
    }

    #[test]
    fn config_parse_accepts_handshake_freshness_secs_override() {
        let mut args = base_args();
        args.push("--handshake-freshness-secs".to_owned());
        args.push("120".to_owned());
        let cfg = Config::parse(args).expect("parse");
        assert_eq!(cfg.handshake_freshness_secs, 120);
    }

    #[test]
    fn config_parse_rejects_non_numeric_freshness_secs() {
        let mut args = base_args();
        args.push("--handshake-freshness-secs".to_owned());
        args.push("not-a-number".to_owned());
        let err = Config::parse(args).expect_err("non-numeric must fail");
        assert!(err.contains("--handshake-freshness-secs"));
    }

    #[test]
    fn config_parse_default_freshness_window_is_600s() {
        let cfg = Config::parse(base_args()).expect("default parse");
        assert_eq!(
            cfg.handshake_freshness_secs, 600,
            "default freshness window is 10 minutes — change with care, mixed-OS handshake refresh cadence varies"
        );
    }
}
