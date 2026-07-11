use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabReadinessState {
    Checking,
    Ready,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabReadiness {
    pub state: LabReadinessState,
    pub detail: String,
}

impl LabReadiness {
    pub fn checking() -> Self {
        Self {
            state: LabReadinessState::Checking,
            detail: "checking tools, privileges, and disk".to_owned(),
        }
    }

    pub fn blocked(detail: impl Into<String>) -> Self {
        Self {
            state: LabReadinessState::Blocked,
            detail: detail.into(),
        }
    }

    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: LabReadinessState::Unknown,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmStatus {
    pub alias: String,
    pub ip: String,
    pub platform: String,
    pub ssh_ok: bool,
    pub power_state: String,
    pub inventory_registered: bool,
    pub lab_readiness: LabReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmVm {
    pub uuid: String,
    pub power_state: String,
    pub name: String,
}

/// Probe a single VM. Platform is supplied by the inventory contract; this
/// module never guesses it from an alias or username.
pub async fn probe_vm(
    alias: &str,
    ip: &str,
    platform: &str,
    power_state: &str,
    inventory_registered: bool,
    cached_readiness: Option<LabReadiness>,
) -> VmStatus {
    let ssh_ok = if power_state != "started" || ip.trim().is_empty() || ip == "-" {
        false
    } else {
        tcp_probe(ip, 22).await
    };

    let lab_readiness = if !inventory_registered {
        LabReadiness::unknown("host VM is not registered in lab inventory")
    } else if power_state != "started" {
        LabReadiness::blocked(format!("power state is {power_state}"))
    } else if !ssh_ok {
        LabReadiness::blocked("SSH is not reachable")
    } else {
        cached_readiness.unwrap_or_else(LabReadiness::checking)
    };

    VmStatus {
        alias: alias.to_string(),
        ip: ip.to_string(),
        platform: platform.to_string(),
        ssh_ok,
        power_state: power_state.to_string(),
        inventory_registered,
        lab_readiness,
    }
}

/// Run the CLI's canonical VM preflight in the background. This checks real
/// guest state: SSH/guest execution, Rust toolchain, Git, privilege, and free
/// disk. Credential handling stays inside rustynet-cli's reviewed transport.
pub async fn probe_lab_readiness(
    repo_root: &Path,
    aliases: &[String],
) -> HashMap<String, LabReadiness> {
    if aliases.is_empty() {
        return HashMap::new();
    }
    let repo_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let Some(binary) = rustynet_cli_binary(&repo_root) else {
        return aliases
            .iter()
            .map(|alias| {
                (
                    alias.clone(),
                    LabReadiness::unknown("rustynet-cli binary not built"),
                )
            })
            .collect();
    };
    let inventory = repo_root.join("documents/operations/active/vm_lab_inventory.json");
    let mut command = tokio::process::Command::new(binary);
    command
        .kill_on_drop(true)
        .current_dir(&repo_root)
        .args(["ops", "vm-lab-preflight", "--inventory"])
        .arg(inventory)
        .args([
            "--require-command",
            "git",
            "--require-command",
            "cargo",
            "--require-command",
            "rustc",
            "--require-command",
            "rustup",
            "--min-free-kib",
            "1048576",
            "--timeout-secs",
            "20",
        ]);
    if let Some(home) = std::env::var_os("HOME") {
        let identity = PathBuf::from(home).join(".ssh/rustynet_lab_ed25519");
        if identity.is_file() {
            command.arg("--ssh-identity-file").arg(identity);
        }
    }
    for alias in aliases {
        command.arg("--vm").arg(alias);
    }

    let output = match tokio::time::timeout(Duration::from_secs(180), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return aliases
                .iter()
                .map(|alias| {
                    (
                        alias.clone(),
                        LabReadiness::unknown(format!("preflight could not start: {err}")),
                    )
                })
                .collect();
        }
        Err(_) => {
            return aliases
                .iter()
                .map(|alias| (alias.clone(), LabReadiness::blocked("preflight timed out")))
                .collect();
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_preflight_readiness(&stdout, aliases).unwrap_or_else(|| {
        aliases
            .iter()
            .map(|alias| {
                (
                    alias.clone(),
                    LabReadiness::unknown("preflight returned unreadable data"),
                )
            })
            .collect()
    })
}

fn rustynet_cli_binary(repo_root: &Path) -> Option<PathBuf> {
    [
        repo_root.join("target/release/rustynet-cli"),
        repo_root.join("target/debug/rustynet-cli"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    .max_by_key(|path| path.metadata().and_then(|meta| meta.modified()).ok())
}

fn parse_preflight_readiness(
    output: &str,
    aliases: &[String],
) -> Option<HashMap<String, LabReadiness>> {
    let report = output.char_indices().find_map(|(idx, ch)| {
        if ch != '{' {
            return None;
        }
        PreflightReport::deserialize(&mut serde_json::Deserializer::from_str(&output[idx..])).ok()
    })?;
    let mut readiness = HashMap::new();
    for result in report.results {
        let state = if result.status == "pass" {
            LabReadiness {
                state: LabReadinessState::Ready,
                detail: "toolchain, Git, privilege, and disk checks passed".to_owned(),
            }
        } else {
            let detail = if !result.problems.is_empty() {
                result
                    .problems
                    .iter()
                    .map(|problem| humanize_preflight_problem(problem))
                    .collect::<Vec<_>>()
                    .join("; ")
            } else {
                result
                    .error
                    .map(|error| humanize_preflight_error(&error))
                    .unwrap_or_else(|| "preflight failed".to_owned())
            };
            LabReadiness::blocked(detail)
        };
        readiness.insert(result.label, state);
    }
    for alias in aliases {
        readiness
            .entry(alias.clone())
            .or_insert_with(|| LabReadiness::unknown("preflight omitted VM"));
    }
    Some(readiness)
}

fn humanize_preflight_problem(problem: &str) -> String {
    if problem == "sudo-n" {
        return "passwordless admin/sudo unavailable".to_owned();
    }
    if let Some(commands) = problem.strip_prefix("missing-commands=") {
        return format!("missing tools: {commands}");
    }
    if problem.starts_with("free_kib<") {
        return "less than 1 GiB free disk".to_owned();
    }
    if problem == "rustynet-missing" {
        return "rustynet binary missing".to_owned();
    }
    problem.to_owned()
}

fn humanize_preflight_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("permission denied") {
        "lab SSH authentication failed".to_owned()
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "guest preflight timed out".to_owned()
    } else {
        error.to_owned()
    }
}

#[derive(Debug, Deserialize)]
struct PreflightReport {
    results: Vec<PreflightResult>,
}

#[derive(Debug, Deserialize)]
struct PreflightResult {
    label: String,
    status: String,
    #[serde(default)]
    problems: Vec<String>,
    error: Option<String>,
}

/// Fetch every VM registered with UTM on this host. Inventory is not used to
/// decide membership; it only enriches these host-owned records later.
pub async fn list_utm_vms() -> Result<Vec<UtmVm>> {
    let bundled = Path::new("/Applications/UTM.app/Contents/MacOS/utmctl");
    let binary = if bundled.is_file() {
        bundled.as_os_str()
    } else {
        std::ffi::OsStr::new("utmctl")
    };
    let output = tokio::process::Command::new(binary)
        .arg("list")
        .output()
        .await
        .context("running utmctl list")?;
    if !output.status.success() {
        bail!(
            "utmctl list failed (status={}): stderr={} stdout={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    let stdout =
        String::from_utf8(output.stdout).context("utmctl list returned non-UTF8 output")?;
    parse_utmctl_list(&stdout)
}

fn parse_utmctl_list(raw: &str) -> Result<Vec<UtmVm>> {
    let mut vms = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        if line_no == 0 && line.trim_start().starts_with("UUID") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(uuid) = fields.next() else {
            continue;
        };
        let power_state = fields
            .next()
            .with_context(|| format!("utmctl row missing status: {line}"))?;
        let name = fields.collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            bail!("utmctl row missing VM name: {line}");
        }
        vms.push(UtmVm {
            uuid: uuid.to_owned(),
            power_state: power_state.to_ascii_lowercase(),
            name,
        });
    }
    Ok(vms)
}

async fn tcp_probe(host: &str, port: u16) -> bool {
    let addr_str = format!("{host}:{port}");
    // Use spawn_blocking so the blocking connect_timeout doesn't stall the runtime
    tokio::task::spawn_blocking(move || {
        // Resolve first
        let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => return false,
        };
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_utm_rows_and_preserves_names_with_spaces() {
        let raw = "UUID Status Name\nA started Debian\nB stopped Windows XP Harness\n";
        let vms = parse_utmctl_list(raw).expect("parse");
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0].name, "Debian");
        assert_eq!(vms[0].power_state, "started");
        assert_eq!(vms[1].name, "Windows XP Harness");
        assert_eq!(vms[1].power_state, "stopped");
    }

    #[test]
    fn parses_preflight_json_from_success_or_cli_error_output() {
        let aliases = vec!["ready-vm".to_owned(), "blocked-vm".to_owned()];
        let body = r#"{
          "results": [
            {"label":"ready-vm","status":"pass","problems":[]},
            {"label":"blocked-vm","status":"fail","problems":["sudo-n","missing-commands=rustup"]}
          ],
          "summary":{"targets":2,"passed":1,"failed":1}
        }"#;
        for output in [
            body.to_owned(),
            format!("error [config]: {body}\n  hint: inspect"),
        ] {
            let parsed = parse_preflight_readiness(&output, &aliases).expect("parse");
            assert_eq!(parsed["ready-vm"].state, LabReadinessState::Ready);
            assert_eq!(parsed["blocked-vm"].state, LabReadinessState::Blocked);
            assert!(parsed["blocked-vm"].detail.contains("passwordless admin"));
            assert!(parsed["blocked-vm"].detail.contains("rustup"));
        }
    }
}
