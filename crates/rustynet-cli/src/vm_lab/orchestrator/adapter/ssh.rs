#![allow(dead_code)]
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
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
            ..
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

/// Attach SSH connection-multiplexing (ControlMaster) options to `cmd`.
///
/// The first connection to a host opens a master; subsequent ssh/scp
/// invocations in the same run reuse it, skipping the TCP + auth handshake.
/// This is a pure latency optimisation and does NOT weaken security:
/// `StrictHostKeyChecking=yes` is still enforced when the master is
/// established, the control socket lives in a per-process directory created
/// mode 0700 (so other local users cannot hijack the multiplexed channel),
/// and `ControlPersist` is short so masters do not outlive the run.
///
/// The `ControlPath` is kept under a short, fixed `/tmp` prefix (not `$TMPDIR`,
/// which on macOS is long) so the resulting Unix-socket path stays well under
/// the ~104-char `sun_path` limit. `%C` is a short hash of (host, port, user,
/// local host), giving one master per distinct target.
fn attach_control_master(cmd: &mut Command) -> Option<String> {
    let dir = format!("/tmp/rn_ssh_cm_{}", std::process::id());
    if std::fs::create_dir_all(&dir).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let control_path = format!("{dir}/cm-%C");
        cmd.args(["-o", "ControlMaster=auto", "-o", "ControlPersist=30s"]);
        cmd.arg("-o").arg(format!("ControlPath={control_path}"));
        return Some(control_path);
    }
    // If the control dir cannot be created we simply omit multiplexing and
    // fall back to a fresh connection per command — correct, just slower.
    None
}

/// Everything needed to tear down a ControlMaster master process with a single
/// argv-only `ssh -O exit` invocation. `ControlPersist=30s` keeps the master —
/// and its copies of the foreground child's stdout/stderr pipe write-ends —
/// alive for up to 30s after the foreground ssh is killed on a per-command
/// timeout. That would block the drain threads' `join()` for the full persist
/// window. Closing the master promptly closes those write-ends so the drains
/// unblock immediately.
struct ControlMasterTeardown {
    host: String,
    port: u16,
    user: Option<String>,
    control_path: String,
}

impl ControlMasterTeardown {
    /// Build the `ssh -O exit` command (argv-only; no shell construction).
    fn into_exit_command(self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-F",
            "/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "BatchMode=yes",
        ]);
        cmd.arg("-O").arg("exit");
        cmd.arg("-o")
            .arg(format!("ControlPath={}", self.control_path));
        cmd.arg("-p").arg(self.port.to_string());
        if let Some(user) = self.user.as_deref() {
            cmd.arg("-l").arg(user);
        }
        cmd.arg("--").arg(&self.host);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd
    }
}

fn base_ssh_command(
    host: &str,
    port: u16,
    user: Option<&str>,
    identity_file: &Path,
    known_hosts: &Path,
) -> (Command, Option<ControlMasterTeardown>) {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-n",
        "-F",
        "/dev/null",
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
    let teardown = attach_control_master(&mut cmd).map(|control_path| ControlMasterTeardown {
        host: host.to_owned(),
        port,
        user: user.map(str::to_owned),
        control_path,
    });
    if let Some(u) = user {
        cmd.arg("-l").arg(u);
    }
    cmd.arg("--").arg(host);
    (cmd, teardown)
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
        "-F",
        "/dev/null",
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
    // scp reuses any master opened by the ssh path; it does not need its own
    // teardown handle (scp runs short and its child exits before any timeout
    // path that would block on a lingering master).
    let _ = attach_control_master(&mut cmd);
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
    run_remote_inner(conn, script, timeout, None)
}

/// Like `run_remote` but also streams stdout+stderr to `log_path` in real time.
/// Creates parent directories if they do not exist. Appends to the file.
pub fn run_remote_with_log(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
    log_path: &Path,
) -> Result<String, AdapterError> {
    if let Some(parent) = log_path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = fs::create_dir_all(parent);
    }
    run_remote_inner(conn, script, timeout, Some(log_path))
}

fn run_remote_inner(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
    log_sink: Option<&Path>,
) -> Result<String, AdapterError> {
    let (host, port, user, identity_file, known_hosts) = ssh_params(conn)?;
    let (mut cmd, control_master_teardown) =
        base_ssh_command(host, port, user, identity_file, known_hosts);
    cmd.arg(script);
    let output = run_output_with_timeout(&mut cmd, timeout, log_sink, control_master_teardown)
        .map_err(|message| AdapterError::Ssh {
            message: format!("SSH spawn failed for {host}: {message}"),
        })?;
    if !output.status.success() {
        let stderr_raw = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        // Windows PowerShell over OpenSSH frequently writes diagnostic
        // detail to stdout (CLIXML stream / Write-Host). When stderr is
        // empty, fall back to a tail of stdout so the operator sees
        // *something* rather than a bare "(exit Some(1)): ".
        let stdout_lossy = String::from_utf8_lossy(&output.stdout);
        let stdout_trimmed = stdout_lossy.trim();
        let stderr = if stderr_raw.is_empty() {
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
        .map(|s| s.trim().to_owned())
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

/// Run `command` with `timeout`. Drains stdout and stderr concurrently in
/// background threads so that pipe buffers never fill and block the child.
/// When `log_sink` is `Some(path)`, each byte is also appended to that file
/// as it arrives, giving live visibility into long-running commands such as
/// `cargo build` during bootstrap.
fn run_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
    log_sink: Option<&Path>,
    control_master_teardown: Option<ControlMasterTeardown>,
) -> Result<std::process::Output, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();

    // Take ownership of the pipes before entering the poll loop.
    let stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stderr_pipe = child.stderr.take().expect("stderr was piped");

    // Open the log file for append when a sink path was provided.
    let log_writer: Option<Arc<Mutex<fs::File>>> = match log_sink {
        Some(path) => {
            let f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("open log sink {}: {e}", path.display()))?;
            Some(Arc::new(Mutex::new(f)))
        }
        None => None,
    };

    // Spawn a thread to drain stdout, optionally tee-ing to the log.
    let out_log = log_writer.clone();
    let stdout_thread = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        let mut pipe = stdout_pipe;
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(ref w) = out_log
                        && let Ok(mut f) = w.lock()
                    {
                        let _ = f.write_all(&chunk[..n]);
                    }
                }
            }
        }
        buf
    });

    // Spawn a thread to drain stderr, optionally tee-ing to the log.
    let err_log = log_writer;
    let stderr_thread = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(ref w) = err_log
                        && let Ok(mut f) = w.lock()
                    {
                        let _ = f.write_all(&chunk[..n]);
                    }
                }
            }
        }
        buf
    });

    // Poll for child exit or timeout.
    let exit_status = loop {
        match child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            Some(status) => break status,
            None => {
                if started_at.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Killing the foreground ssh child does NOT close the
                    // ControlMaster master's copies of the stdout/stderr pipe
                    // write-ends; with ControlPersist=30s the drain threads
                    // would otherwise block on join() until the master expires.
                    // Tear the master down now (argv-only `ssh -O exit`) so the
                    // write-ends close and the drains unblock promptly. Best
                    // effort: a missing/already-gone master is harmless.
                    if let Some(teardown) = control_master_teardown {
                        teardown_control_master(teardown);
                    }
                    // Flush remaining log data before returning.
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(format!("timed out after {} seconds", timeout.as_secs()));
                }
                thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
            }
        }
    };

    // Join reader threads to collect all output (pipes closed when child exited).
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    Ok(std::process::Output {
        status: exit_status,
        stdout,
        stderr,
    })
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

/// Decide whether a daemon `*-check` JSON report indicates success.
///
/// The daemon prints a report whose top-level `overall_ok` boolean is the
/// verdict — there is NO `passed` field. The orchestrator runs every check with
/// `--no-fail-on-drift`, so the daemon exits 0 and prints the report even when
/// it detected drift; the verdict must therefore be read from the report body,
/// not the process exit code.
///
/// Fail closed: returns `true` only when `overall_ok: true` is present AND
/// `overall_ok: false` is absent. Empty, truncated, non-JSON, field-missing, or
/// `false` output all return `false`. Substring matching (rather than strict
/// JSON parsing) is deliberate: a check whose stdout has stderr merged into it,
/// is pretty-printed across multiple lines, or carries a leading log line is
/// still evaluated correctly instead of fail-closing on output that is valid
/// but not a single parseable JSON value.
pub fn validator_report_ok(output: &str) -> bool {
    let has_ok = output.contains("\"overall_ok\": true") || output.contains("\"overall_ok\":true");
    let has_not_ok =
        output.contains("\"overall_ok\": false") || output.contains("\"overall_ok\":false");
    has_ok && !has_not_ok
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

fn teardown_control_master(teardown: ControlMasterTeardown) {
    let mut cmd = teardown.into_exit_command();
    if let Ok(mut child) = cmd.spawn() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlMasterTeardown, validator_report_ok};

    #[test]
    fn control_master_teardown_builds_argv_only_ssh_o_exit() {
        // The control-socket teardown that runs on a per-command timeout must
        // be argv-only `ssh -O exit` for the exact ControlPath — never shell
        // construction. Verify the argv carries `-O exit`, the ControlPath, the
        // port, the user, and the host past the `--` separator, with no shell.
        let teardown = ControlMasterTeardown {
            host: "192.168.64.3".to_owned(),
            port: 22,
            user: Some("debian".to_owned()),
            control_path: "/tmp/rn_ssh_cm_4242/cm-%C".to_owned(),
        };
        let cmd = teardown.into_exit_command();
        assert_eq!(cmd.get_program(), "ssh");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // `-O exit` tears down the master.
        let o_idx = args.iter().position(|a| a == "-O").expect("-O present");
        assert_eq!(args[o_idx + 1], "exit");
        // Exact ControlPath so we target the right socket.
        assert!(
            args.iter()
                .any(|a| a == "ControlPath=/tmp/rn_ssh_cm_4242/cm-%C"),
            "argv must carry the exact ControlPath: {args:?}"
        );
        // Port + user + host present, host after the `--` separator.
        assert!(args.iter().any(|a| a == "22"), "port present: {args:?}");
        assert!(args.iter().any(|a| a == "debian"), "user present: {args:?}");
        let sep = args.iter().position(|a| a == "--").expect("-- present");
        assert_eq!(args[sep + 1], "192.168.64.3");
    }

    #[test]
    fn control_master_teardown_omits_user_when_none() {
        let teardown = ControlMasterTeardown {
            host: "host.example".to_owned(),
            port: 2200,
            user: None,
            control_path: "/tmp/rn_ssh_cm_1/cm-%C".to_owned(),
        };
        let cmd = teardown.into_exit_command();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a == "-l"),
            "no -l when user None: {args:?}"
        );
        assert!(args.iter().any(|a| a == "2200"));
    }

    #[test]
    fn validator_report_ok_true_only_on_explicit_overall_ok_true() {
        // Pretty-printed (spaced) form the daemon emits via to_string_pretty.
        assert!(validator_report_ok(
            "{\n  \"overall_ok\": true,\n  \"drift_reasons\": []\n}"
        ));
        // Compact form.
        assert!(validator_report_ok("{\"overall_ok\":true}"));
        // Tolerant of a merged stderr log line preceding the JSON.
        assert!(validator_report_ok(
            "WARN something\n{\n  \"overall_ok\": true\n}"
        ));
    }

    #[test]
    fn validator_report_ok_fails_closed() {
        // Drift reported.
        assert!(!validator_report_ok(
            "{\n  \"overall_ok\": false,\n  \"drift_reasons\": [\"x\"]\n}"
        ));
        // Field absent (e.g. wrong schema / old `passed` schema) → fail closed.
        assert!(!validator_report_ok("{\"passed\": true}"));
        // Empty / non-JSON output → fail closed.
        assert!(!validator_report_ok(""));
        assert!(!validator_report_ok("command not found"));
        // Both present (top-level false plus a nested true) → fail closed.
        assert!(!validator_report_ok(
            "{\"overall_ok\": false, \"sub\": {\"overall_ok\": true}}"
        ));
    }
}
