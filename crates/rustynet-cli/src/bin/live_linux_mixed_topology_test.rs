#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

//! Track B Phase 12 — mixed-OS topology integration validator.
//!
//! Closes Track B with a single live-lab stage that proves Linux,
//! macOS, and Windows nodes share one signed membership view AND
//! see each other in their per-host `rustynet anchor list` output.
//!
//! Track B Phases 4-11 land per-host validators (exit-handoff /
//! relay-service-lifecycle / anchor) that prove each platform
//! correctly runs its role in isolation. Phase 12 is the
//! convergence check: it captures `rustynet anchor list` from all
//! three hosts in one orchestrator pass and asserts that every host
//! observes every OTHER host. That's the minimum proof of "different
//! OS communicating without issue" the user asked for at the start
//! of Track B.
//!
//! The bin reuses the cross-platform anchor-list capture from
//! `live_linux_anchor_test.rs` so the dispatch matrix and the
//! sudo/admin preflights stay in lockstep across both bins.
//!
//! Substages:
//!   1. capture_anchor_list_each_host — drive `rustynet anchor list`
//!      on each of the three nodes (Linux via systemctl + sudo,
//!      macOS via launchd + sudo -n, Windows via PowerShell over
//!      SSH-Administrator).
//!   2. verify_mutual_membership_visibility — every host must list
//!      every other host's node_id in its anchor table.
//!   3. emit_topology_report — canonical envelope (phase, mode,
//!      evidence_mode, captured_at, captured_at_unix, git_commit,
//!      source_artifacts, status) with a per-host coverage matrix.
//!
//! The validator fails closed when any host cannot be reached, any
//! host's anchor list is missing a peer it should observe, or any
//! capture errors out. There is no PASS without ALL hosts present
//! in ALL views.

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    capture_remote_stdout, capture_root, create_workspace, ensure_pinned_known_hosts_file,
    ensure_safe_token, git_head_commit, load_home_known_hosts_path, repo_root, require_command,
    seed_known_hosts, verify_passwordless_sudo, verify_sudo, verify_windows_admin, write_file,
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

    // Capture `rustynet anchor list` on each host. Drop into a
    // per-host record so the report can show which view came from
    // where.
    let mut views: Vec<HostView> = Vec::with_capacity(hosts.len());
    for host in &hosts {
        let anchor_list = capture_anchor_list(
            &config.ssh_identity_file,
            &work_known_hosts,
            host.target.as_str(),
            host.platform,
        )
        .map_err(|err| {
            format!(
                "rustynet anchor list capture failed for {} ({}): {err}",
                host.label,
                host.platform.as_str()
            )
        })?;
        let observed = parse_observed_node_ids(anchor_list.as_str());
        views.push(HostView {
            label: host.label.clone(),
            target: host.target.clone(),
            platform: host.platform,
            node_id: host.node_id.clone(),
            observed,
            raw_anchor_list_excerpt: first_lines(anchor_list.as_str(), 24),
        });
    }

    // Verify mutual visibility — every host must see every OTHER
    // host's node_id in its anchor list.
    let mut failures: Vec<String> = Vec::new();
    for view in &views {
        for other in &hosts {
            if other.node_id == view.node_id {
                continue;
            }
            if !view.observed.iter().any(|node| node == &other.node_id) {
                failures.push(format!(
                    "{} ({}) does NOT observe peer {} ({}) in its anchor list",
                    view.label,
                    view.platform.as_str(),
                    other.label,
                    other.node_id,
                ));
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
    raw_anchor_list_excerpt: String,
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
         \x20\x20--known-hosts <path>              pinned SSH known_hosts\n\
         \x20\x20--report-path <path>              JSON report output\n\
         \x20\x20--log-path <path>                 human-readable log output\n\
         \x20\x20--git-commit <sha>                override RUSTYNET_EXPECTED_GIT_COMMIT"
    );
}

// ─── per-platform `rustynet anchor list` capture ──────────────────

/// Same shape as `live_linux_anchor_test.rs::capture_anchor_list_from_host`,
/// reproduced here so the two bins stay independent (each bin can be
/// renamed / rewritten / dropped without breaking the other). The
/// Windows path runs PowerShell directly — Windows SSH session is
/// already Administrator and has no sudo.
fn capture_anchor_list(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    platform: HostPlatform,
) -> Result<String, String> {
    match platform {
        HostPlatform::Linux | HostPlatform::Macos => {
            let command = "command -v rustynet >/dev/null; rustynet anchor list";
            capture_root(identity, known_hosts, host, command)
        }
        HostPlatform::Windows => {
            // Use `if (-not (Get-Command ...))` so a missing
            // `rustynet.exe` short-circuits with an explicit
            // diagnostic. The Phase 11 reviewer flagged the naive
            // `Get-Command | Out-Null` pattern as not actually
            // short-circuiting — it just drops stdout and lets the
            // second statement throw later.
            let command = "powershell -NoProfile -Command \"if (-not (Get-Command rustynet.exe -ErrorAction SilentlyContinue)) { Write-Error 'rustynet.exe not on PATH'; exit 1 }; rustynet.exe anchor list\"";
            capture_remote_stdout(identity, known_hosts, host, command)
        }
    }
}

/// Parse `rustynet anchor list` stdout into the set of node ids the
/// daemon advertises. The canonical format (see
/// `crates/rustynet-cli/src/main.rs::render_anchor_list`) is
/// `<node_id> capabilities=<csv>` lines, prefixed by an `anchor
/// nodes:` header. Pull the node id from each line that contains
/// `capabilities=` so a header / blank line does not pollute the
/// observed set.
fn parse_observed_node_ids(anchor_list: &str) -> Vec<String> {
    let mut out: Vec<String> = anchor_list
        .lines()
        .filter_map(|line| {
            line.split_once(" capabilities=")
                .map(|(node_id, _)| node_id.trim().to_owned())
        })
        .filter(|node_id| !node_id.is_empty() && node_id != "anchor nodes:")
        .collect();
    out.sort();
    out.dedup();
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
    fn parse_observed_node_ids_extracts_each_node_from_anchor_list() {
        let body = "anchor nodes:\n\
                    exit-1 capabilities=anchor,relay_host,anchor.gossip_seed\n\
                    relay-mac capabilities=anchor,relay_host\n\
                    client-win capabilities=client\n";
        let observed = super::parse_observed_node_ids(body);
        assert_eq!(observed, vec!["client-win", "exit-1", "relay-mac"]);
    }

    #[test]
    fn parse_observed_node_ids_returns_empty_for_header_only() {
        let body = "anchor nodes:\n";
        let observed = super::parse_observed_node_ids(body);
        assert!(observed.is_empty());
    }

    #[test]
    fn parse_observed_node_ids_dedupes_repeated_node_id() {
        // Defense-in-depth: if the daemon ever emits a duplicate row,
        // the observed set must not double-count.
        let body = "anchor nodes:\n\
                    exit-1 capabilities=anchor\n\
                    exit-1 capabilities=anchor,relay_host\n";
        let observed = super::parse_observed_node_ids(body);
        assert_eq!(observed, vec!["exit-1"]);
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
            raw_anchor_list_excerpt: "anchor nodes:\nexit-1 capabilities=anchor".to_owned(),
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
        assert_eq!(
            parsed["views"][0]["target"], "debian@192.168.18.49 \" inject \n more",
            "embedded quote/newline must survive serde escaping"
        );
    }
}
