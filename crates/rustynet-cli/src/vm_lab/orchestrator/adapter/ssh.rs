#![allow(dead_code)]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::AdapterError;

const POLL_INTERVAL_MILLIS: u64 = 100;

// ── Connection helpers ────────────────────────────────────────────────────────

/// Extract SSH connection parameters from a `NodeConnection`.
/// Returns `Err` if `conn` is not `NodeConnection::Ssh`.
pub fn ssh_params(
    conn: &NodeConnection,
) -> Result<(&str, u16, Option<&str>, &Path, &Path), AdapterError> {
    match conn {
        NodeConnection::Ssh {
            host,
            port,
            user,
            identity_file,
            known_hosts,
        } => Ok((
            host.as_str(),
            *port,
            user.as_deref(),
            identity_file.as_path(),
            known_hosts.as_path(),
        )),
        other => Err(AdapterError::Ssh {
            message: format!(
                "SSH operations require NodeConnection::Ssh; got '{}'",
                other.kind_label()
            ),
        }),
    }
}

// ── Command builders ──────────────────────────────────────────────────────────

fn base_ssh_command(
    host: &str,
    port: u16,
    user: Option<&str>,
    identity_file: &Path,
    known_hosts: &Path,
) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-n",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "IdentitiesOnly=yes",
        "-p",
        &port.to_string(),
    ]);
    cmd.arg("-i").arg(identity_file);
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    if let Some(u) = user {
        cmd.arg("-l").arg(u);
    }
    cmd.arg("--").arg(host);
    cmd
}

fn base_scp_command(
    port: u16,
    identity_file: &Path,
    known_hosts: &Path,
    user: Option<&str>,
) -> Command {
    let mut cmd = Command::new("scp");
    cmd.args([
        "-q",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "IdentitiesOnly=yes",
        "-P",
        &port.to_string(),
    ]);
    cmd.arg("-i").arg(identity_file);
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    if let Some(u) = user {
        cmd.arg("-o").arg(format!("User={u}"));
    }
    cmd
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run `script` on the remote host over SSH. Returns trimmed stdout on success.
/// Non-zero exit code → `AdapterError::Command`.
pub fn run_remote(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<String, AdapterError> {
    let (host, port, user, identity_file, known_hosts) = ssh_params(conn)?;
    let mut cmd = base_ssh_command(host, port, user, identity_file, known_hosts);
    cmd.arg(script);
    let output =
        run_output_with_timeout(&mut cmd, timeout).map_err(|message| AdapterError::Ssh {
            message: format!("SSH spawn failed for {host}: {message}"),
        })?;
    if !output.status.success() {
        let stderr_raw = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Windows PowerShell over OpenSSH frequently writes diagnostic
        // detail to stdout (CLIXML stream / Write-Host). When stderr is
        // empty, fall back to a tail of stdout so the operator sees
        // *something* rather than a bare "(exit Some(1)): ".
        let stdout_lossy = String::from_utf8_lossy(&output.stdout);
        let stdout_trimmed = stdout_lossy.trim();
        let stderr = if stderr_raw.is_empty() {
            // Windows PowerShell over OpenSSH frequently writes diagnostic
            // detail to stdout (CLIXML stream / Write-Host). When stderr is
            // empty, fall back to a tail of stdout so the operator sees
            // *something* rather than a bare "(exit Some(1)): ".
            if stdout_trimmed.is_empty() {
                String::new()
            } else {
                let tail: String = stdout_trimmed
                    .chars()
                    .rev()
                    .take(800)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("(stderr empty; stdout tail) {tail}")
            }
        } else if !stdout_trimmed.is_empty() {
            // Both streams have content. Cargo writes progress to stderr; the
            // rustynet binary writes errors to stdout via println!. Combine
            // tails from both so the operator sees the actual failure message.
            let stderr_tail: String = stderr_raw
                .chars()
                .rev()
                .take(600)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let stdout_tail: String = stdout_trimmed
                .chars()
                .rev()
                .take(400)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{stderr_tail}\n[stdout: {stdout_tail}]")
        } else {
            stderr_raw
        };
        let code = output.status.code();
        return Err(AdapterError::Command {
            exit_code: code,
            stderr,
        });
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|err| AdapterError::Protocol {
            message: format!("remote output was not valid UTF-8: {err}"),
        })
}

/// Run `script` on the remote host. Returns `true` if exit code is 0.
/// Never returns `Err` for non-zero exit — use this only for boolean probes.
pub fn run_remote_check(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<bool, AdapterError> {
    match run_remote(conn, script, timeout) {
        Ok(_) => Ok(true),
        Err(AdapterError::Command { .. }) => Ok(false),
        Err(other) => Err(other),
    }
}

/// SCP a local file to the remote host.
pub fn scp_to(
    conn: &NodeConnection,
    local: &Path,
    remote_dst: &str,
    timeout: Duration,
) -> Result<(), AdapterError> {
    let (host, port, user, identity_file, known_hosts) = ssh_params(conn)?;
    let mut cmd = base_scp_command(port, identity_file, known_hosts, user);
    cmd.arg("--")
        .arg(local.as_os_str())
        .arg(format!("{host}:{remote_dst}"));
    let status =
        run_status_with_timeout(&mut cmd, timeout).map_err(|message| AdapterError::Ssh {
            message: format!("SCP to {host}:{remote_dst} failed: {message}"),
        })?;
    if !status.success() {
        return Err(AdapterError::Command {
            exit_code: status.code(),
            stderr: format!("scp to {host}:{remote_dst} exited with status {status}"),
        });
    }
    Ok(())
}

/// SCP a file from the remote host to a local path.
pub fn scp_from(
    conn: &NodeConnection,
    remote_src: &str,
    local_dst: &Path,
    timeout: Duration,
) -> Result<(), AdapterError> {
    let (host, port, user, identity_file, known_hosts) = ssh_params(conn)?;
    if let Some(parent) = local_dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local scp destination dir failed: {err}"),
        })?;
    }
    let mut cmd = base_scp_command(port, identity_file, known_hosts, user);
    cmd.arg("--")
        .arg(format!("{host}:{remote_src}"))
        .arg(local_dst.as_os_str());
    let status =
        run_status_with_timeout(&mut cmd, timeout).map_err(|message| AdapterError::Ssh {
            message: format!("SCP from {host}:{remote_src} failed: {message}"),
        })?;
    if !status.success() {
        return Err(AdapterError::Command {
            exit_code: status.code(),
            stderr: format!("scp from {host}:{remote_src} exited with status {status}"),
        });
    }
    Ok(())
}

/// Poll until `socket_path` exists on the remote (a UNIX domain socket file).
/// Returns `Err` if the socket does not appear within `timeout`.
pub fn wait_for_remote_socket(
    conn: &NodeConnection,
    socket_path: &str,
    timeout: Duration,
) -> Result<(), AdapterError> {
    let deadline = Instant::now() + timeout;
    let poll = Duration::from_millis(500);
    let script = format!("test -S {socket_path}");
    loop {
        if run_remote_check(conn, &script, Duration::from_secs(10))? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AdapterError::Ssh {
                message: format!("daemon socket {socket_path} did not appear within {timeout:?}"),
            });
        }
        thread::sleep(poll);
    }
}

// ── Private runtime helpers ───────────────────────────────────────────────────

fn run_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|err| format!("collect output failed: {err}"));
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

fn run_status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            return Ok(status);
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

/// Parse the `node_id=<value>` field from a `rustynet status` output line.
/// The status response is `key=value key=value …` space-separated.
pub fn parse_status_node_id(status_text: &str) -> Option<String> {
    status_text.split_whitespace().find_map(|field| {
        field
            .strip_prefix("node_id=")
            .map(std::string::ToString::to_string)
    })
}

/// Parse any `key=<value>` field from a `rustynet status` space-separated output.
pub fn parse_status_field(status_text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status_text.split_whitespace().find_map(|field| {
        field
            .strip_prefix(prefix.as_str())
            .map(std::string::ToString::to_string)
    })
}

// ── Build remote path for a host+user combination ────────────────────────────

pub fn remote_home(user: Option<&str>) -> &'static str {
    match user {
        Some("root") | None => "/root",
        _ => "/home/",
    }
}

pub fn remote_home_for_user(user: Option<&str>, heap_user: &str) -> PathBuf {
    match user {
        Some("root") => PathBuf::from("/root"),
        Some(u) => PathBuf::from(format!("/home/{u}")),
        None => PathBuf::from(format!("/home/{heap_user}")),
    }
}
