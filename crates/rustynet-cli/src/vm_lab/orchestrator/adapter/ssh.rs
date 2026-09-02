#![allow(dead_code)]
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::AdapterError;
use crate::vm_lab::{AllowEmpty, ensure_single_quoted_script_value, shell_quote};

const POLL_INTERVAL_MILLIS: u64 = 100;

/// Upper bound on the decoded PowerShell error text appended to an
/// `AdapterError::Command` message. Long enough for a multi-line PowerShell
/// error record, short enough that it cannot crowd out the raw prefix.
const POWERSHELL_ERROR_RENDER_LIMIT: usize = 1200;

// ── PowerShell CLIXML rendering (W-FIX-2) ────────────────────────────────────

/// Build the `stderr` payload of an `AdapterError::Command` from a failed
/// remote command's two streams.
///
/// This is the single seam where captured output becomes the operator-visible
/// `error_detail`. It changes nothing about what is *captured* — both raw
/// buffers arrive intact — it only decides what the rendered summary says.
fn render_command_failure_detail(stderr_raw: &str, stdout_trimmed: &str) -> String {
    // Windows PowerShell over OpenSSH frequently writes diagnostic detail to
    // stdout (CLIXML stream / Write-Host). When stderr is empty, fall back to
    // a tail of stdout so the operator sees *something* rather than a bare
    // "(exit Some(1)): ".
    let base = if stderr_raw.is_empty() {
        if stdout_trimmed.is_empty() {
            String::new()
        } else {
            format!(
                "(stderr empty; stdout tail) {}",
                tail_chars(stdout_trimmed, 800)
            )
        }
    } else if !stdout_trimmed.is_empty() {
        // Both streams have content. Cargo writes progress to stderr; the
        // rustynet binary writes errors to stdout via println!. Combine tails
        // from both so the operator sees the actual failure message.
        format!(
            "{}\n[stdout: {}]",
            tail_chars(stderr_raw, 600),
            tail_chars(stdout_trimmed, 400)
        )
    } else {
        stderr_raw.to_owned()
    };

    // Append the decoded PowerShell error record, if the guest sent one. It
    // goes LAST on purpose: the tails above and the ledger's `error_detail`
    // column both truncate from the FRONT, which is how
    // "Configuration is not enabled. Run `winget configure --enable`" ended up
    // cut out of the operator-visible error while sitting in the same buffer.
    // Appending puts the readable sentence where front-truncation cannot reach
    // it, and leaves the raw CLIXML in the prefix — the Rust `--node` engine
    // writes its per-stage log from this same summary
    // (`orchestrator/evidence.rs`), so the raw form has nowhere else to
    // survive and must not be discarded here.
    match render_powershell_clixml_error(stderr_raw)
        .or_else(|| render_powershell_clixml_error(stdout_trimmed))
    {
        Some(decoded) => format!("{base}\n[powershell error: {decoded}]"),
        None => base,
    }
}

/// Last `limit` characters of `text`, char-wise (never splits a code point).
fn tail_chars(text: &str, limit: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let start = chars.len().saturating_sub(limit);
    chars[start..].iter().collect()
}

/// Decode the human-readable text out of a PowerShell CLIXML error stream.
///
/// Windows guests are driven over OpenSSH by invoking `powershell.exe`, whose
/// non-stdout streams are serialized as CLIXML. On the SSH adapter path that
/// payload went into `AdapterError::Command`'s `stderr` verbatim, and
/// `error.rs` renders `stderr` verbatim in turn — so the operator-visible
/// `error_detail` was a wall of `<S S="Error">...</S>` fragments with
/// `_x000D__x000A_` escapes, while the sentence naming the actual cause was
/// unreadable inside it. That is the diagnosability defect §5 of
/// `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` blames for CP-4 sitting
/// open for five weeks.
///
/// This is deliberately a DECODER, not a filter. The `utmctl exec` path's
/// [`strip_powershell_clixml_noise`](crate::vm_lab::strip_powershell_clixml_noise)
/// *drops* the envelope, which is right there: on that path the CLIXML is
/// progress-record noise wrapped around a plain-text host error. On the SSH
/// path the CLIXML **is** the error record, so dropping it would delete the
/// only copy of the message. We therefore decode the `<S>` string records and
/// fall back to the existing stripper when there are none.
///
/// Returns `None` when the input carries no CLIXML — non-PowerShell stderr
/// (Linux, macOS, scp, ssh's own errors) must pass through untouched.
fn render_powershell_clixml_error(raw: &str) -> Option<String> {
    if !raw.contains("#< CLIXML") && !raw.contains("<S ") && !raw.contains("<S>") {
        return None;
    }

    let records = extract_clixml_string_records(raw);
    let decoded = if records.is_empty() {
        // No `<S>` records to decode: this is the envelope-only shape the
        // utmctl path already handles, so reuse the stripper the repo owns.
        crate::vm_lab::strip_powershell_clixml_noise(raw)
    } else {
        records.join("")
    };

    let cleaned = decoded
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }
    let truncated: String = cleaned
        .chars()
        .take(POWERSHELL_ERROR_RENDER_LIMIT)
        .collect();
    Some(truncated)
}

/// Pull the inner text out of every `<S ...>...</S>` element, in document
/// order, decoding CLIXML's `_xHHHH_` escapes and XML entities as it goes.
fn extract_clixml_string_records(raw: &str) -> Vec<String> {
    let mut records = Vec::new();
    let mut rest = raw;
    while let Some(open_start) = rest.find("<S") {
        let after_tag_name = &rest[open_start + 2..];
        // `<S>` or `<S S="Error">` — but not `<Something>`.
        if !after_tag_name.starts_with('>') && !after_tag_name.starts_with(' ') {
            rest = &rest[open_start + 2..];
            continue;
        }
        let Some(open_end) = after_tag_name.find('>') else {
            break;
        };
        let body_start = open_start + 2 + open_end + 1;
        let Some(close_rel) = rest[body_start..].find("</S>") else {
            break;
        };
        records.push(decode_clixml_text(
            &rest[body_start..body_start + close_rel],
        ));
        rest = &rest[body_start + close_rel + 4..];
    }
    records
}

/// Decode one CLIXML text node: `_xHHHH_` character escapes first (CR/LF are
/// the ones that matter — they are what makes the raw form unreadable), then
/// the XML entities PowerShell escapes on top of them.
fn decode_clixml_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes: Vec<char> = text.chars().collect();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == '_'
            && idx + 6 < bytes.len()
            && (bytes[idx + 1] == 'x' || bytes[idx + 1] == 'X')
            && bytes[idx + 6] == '_'
            && let Some(decoded) = decode_hex_escape(&bytes[idx + 2..idx + 6])
        {
            out.push(decoded);
            idx += 7;
            continue;
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    decode_xml_entities(&out)
}

fn decode_hex_escape(digits: &[char]) -> Option<char> {
    let mut value: u32 = 0;
    for ch in digits {
        value = value * 16 + ch.to_digit(16)?;
    }
    // Carriage returns only add noise once line endings are normalized.
    if value == u32::from(b'\r') {
        return Some('\n');
    }
    char::from_u32(value)
}

fn decode_xml_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail.find(';').filter(|semi| *semi <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            other => other
                .strip_prefix('#')
                .and_then(
                    |num| match num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => num.parse::<u32>().ok(),
                    },
                )
                .and_then(char::from_u32),
        };
        match decoded {
            Some(ch) => {
                out.push(ch);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

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

/// The `-o` connection-hardening options shared by EVERY ssh/scp invocation in
/// this module. Named in one place so a test can assert both transports carry
/// the full set — a security-relevant flag (StrictHostKeyChecking, BatchMode,
/// IdentitiesOnly, ConnectTimeout, LogLevel) can no longer be added to the ssh
/// path but silently forgotten on the scp path or vice-versa.
const SHARED_HARDENING_O_FLAGS: &[&str] = &[
    "LogLevel=ERROR",
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "ConnectTimeout=15",
    "IdentitiesOnly=yes",
];

/// Append the shared security posture to `cmd`: `-F /dev/null` (ignore system
/// ssh_config), the [`SHARED_HARDENING_O_FLAGS`], the pinned identity key, and
/// the pinned known-hosts file. Protocol-level differences (ssh `-p`/`-l`/`-n`
/// vs scp `-P`/`-o User=`/`-q`, keepalives, ControlMaster teardown) are
/// deliberately NOT here — each builder adds those itself.
fn attach_shared_hardening(cmd: &mut Command, identity_file: &Path, known_hosts: &Path) {
    cmd.args(["-F", "/dev/null"]);
    for flag in SHARED_HARDENING_O_FLAGS {
        cmd.arg("-o").arg(*flag);
    }
    cmd.arg("-i").arg(identity_file);
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
}

fn base_ssh_command(
    host: &str,
    port: u16,
    user: Option<&str>,
    identity_file: &Path,
    known_hosts: &Path,
) -> (Command, Option<ControlMasterTeardown>) {
    let mut cmd = Command::new("ssh");
    cmd.arg("-n");
    attach_shared_hardening(&mut cmd, identity_file, known_hosts);
    // ssh-only: keepalives for long-lived sessions (bootstrap builds) + the
    // lowercase `-p` port flag.
    cmd.args([
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        &port.to_string(),
    ]);
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
    cmd.arg("-q");
    attach_shared_hardening(&mut cmd, identity_file, known_hosts);
    // scp-only: the uppercase `-P` port flag, and the login name via
    // `-o User=` (scp has no `-l`).
    cmd.arg("-P").arg(port.to_string());
    // scp reuses any master opened by the ssh path; it does not need its own
    // teardown handle (scp runs short and its child exits before any timeout
    // path that would block on a lingering master).
    let _ = attach_control_master(&mut cmd);
    if let Some(u) = user {
        cmd.arg("-o").arg(format!("User={u}"));
    }
    cmd
}

// ── QH-01: validated remote-command newtypes ─────────────────────────────────

/// A remote command that is safe to hand to the SSH sink family.
///
/// The field is private and there is deliberately no `From<String>`: the only
/// ways in are a `script_template` render output or a validator-checked value,
/// so holding a `RemoteCommand` is proof the injection boundary was crossed
/// deliberately. There is no `Display`; `Debug` prints the length only, never
/// the payload. `as_str` exists solely so the sink functions in this module
/// can lower the value into `cmd.arg(...)` — it must not leak further.
pub(crate) struct RemoteCommand(String);

impl RemoteCommand {
    // Deliberately NO constructor from a plain `String`: the renderer's
    // `render_*` functions return `String` today, so a "from rendered
    // template" constructor would accept any `format!` result and void the
    // compile-time proof this type exists for. Step 4d adds the typed
    // renderer-output constructor together with the sink signature flip.

    /// Wrap a single value after quote-safety validation and shell quoting.
    /// `label` names the argument for the error message.
    pub(crate) fn from_validated_single(label: &str, value: &str) -> Result<Self, AdapterError> {
        ensure_single_quoted_script_value(label, value, AllowEmpty::No).map_err(|reason| {
            AdapterError::Protocol {
                message: format!("{label}: {reason}"),
            }
        })?;
        Ok(Self(shell_quote(value)))
    }

    /// Build a command from validated arguments: each is shell-quoted and the
    /// results are space-joined. Validation already happened at
    /// [`ValidatedArg`] construction, so a value that would break out of
    /// quoting is rejected before any command string exists.
    pub(crate) fn from_args(label: &str, args: &[ValidatedArg]) -> Result<Self, AdapterError> {
        if args.is_empty() {
            return Err(AdapterError::Protocol {
                message: format!("{label}: no validated arguments supplied"),
            });
        }
        let joined = args
            .iter()
            .map(ValidatedArg::quoted)
            .collect::<Vec<_>>()
            .join(" ");
        Ok(Self(joined))
    }

    /// Sink-only accessor: the run_remote sink family in THIS module lowers
    /// this into `cmd.arg(...)`. Do not use it to re-interpolate the payload
    /// into another string.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RemoteCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: a remote command may embed hostnames and user data; only
        // its length may reach logs.
        write!(f, "RemoteCommand(len={})", self.0.len())
    }
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
        let stdout_lossy = String::from_utf8_lossy(&output.stdout);
        let code = output.status.code();
        return Err(AdapterError::Command {
            exit_code: code,
            stderr: render_command_failure_detail(&stderr_raw, stdout_lossy.trim()),
        });
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|err| AdapterError::Protocol {
            message: format!("remote output was not valid UTF-8: {err}"),
        })
}

/// Run an **idempotent, side-effect-free** `script` over SSH, retrying transient
/// failures. Returns trimmed stdout on the first success.
///
/// A first-connection SSH failure (`ConnectTimeout` expiry, `Operation timed
/// out`) surfaces as ssh's own exit 255 — an `AdapterError::Command`, not
/// `AdapterError::Ssh` — so this retries on *any* error. That is only safe for
/// read-only probes (OS-version capture, reachability), never for a mutation.
/// Between attempts it sleeps `backoff`, doubling up to a 5s cap, so a single
/// transient first-connection timeout no longer decides the whole probe.
pub fn run_remote_retrying(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
    attempts: u32,
    backoff: Duration,
) -> Result<String, AdapterError> {
    let attempts = attempts.max(1);
    let mut last_err: Option<AdapterError> = None;
    let mut wait = backoff;
    for attempt in 1..=attempts {
        match run_remote(conn, script, timeout) {
            Ok(out) => return Ok(out),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    thread::sleep(wait);
                    wait = (wait * 2).min(Duration::from_secs(5));
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AdapterError::Ssh {
        message: "run_remote_retrying exhausted attempts with no captured error".to_owned(),
    }))
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
///
/// Retries transport-layer failures (our timeout wrapper, or scp/ssh's own
/// exit 255) up to two more times with a short backoff. A file copy is
/// idempotent, and on a real cross-LAN path transient connection failures
/// are routine — run livelab-1787836555 lost both lenovo guests to exit-255
/// scp failures while the link sat at 80-100ms RTT, then reached them fine
/// seconds later. Non-transport failures (permission, missing path — any
/// exit code other than 255) still fail on the first attempt.
pub fn scp_to(
    conn: &NodeConnection,
    local: &Path,
    remote_dst: &str,
    timeout: Duration,
) -> Result<(), AdapterError> {
    let (host, port, user, identity_file, known_hosts) = ssh_params(conn)?;
    let mut last_err: Option<AdapterError> = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(3 * u64::from(attempt)));
        }
        let mut cmd = base_scp_command(port, identity_file, known_hosts, user);
        cmd.arg("--")
            .arg(local.as_os_str())
            .arg(format!("{host}:{remote_dst}"));
        match run_status_with_timeout(&mut cmd, timeout) {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                let err = AdapterError::Command {
                    exit_code: status.code(),
                    stderr: format!("scp to {host}:{remote_dst} exited with status {status}"),
                };
                if status.code() != Some(255) {
                    return Err(err);
                }
                last_err = Some(err);
            }
            Err(message) => {
                last_err = Some(AdapterError::Ssh {
                    message: format!("SCP to {host}:{remote_dst} failed: {message}"),
                });
            }
        }
    }
    Err(last_err.unwrap_or(AdapterError::Ssh {
        message: format!("SCP to {host}:{remote_dst} failed with no recorded error"),
    }))
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
/// The status response is `key=value key=value …` space-separated. Thin,
/// well-named alias over [`parse_status_field`] so there is one parsing
/// implementation to keep correct.
pub fn parse_status_node_id(status_text: &str) -> Option<String> {
    parse_status_field(status_text, "node_id")
}

/// Decide whether a daemon `*-check` JSON report indicates success.
///
/// The daemon prints a report whose top-level `overall_ok` boolean is the
/// verdict — there is NO `passed` field. The orchestrator runs every check with
/// `--no-fail-on-drift`, so the daemon exits 0 and prints the report even when
/// it detected drift; the verdict must therefore be read from the report body,
/// not the process exit code.
///
/// The verdict is read from TYPED JSON, not from a raw substring. Every balanced
/// JSON object in the output is parsed (a check whose stdout has stderr merged
/// into it, is pretty-printed across multiple lines, or carries a leading log
/// line is still evaluated correctly), and each parsed object is judged by its
/// TOP-LEVEL `overall_ok` field only. Fail closed, QH-39 finding 2:
///
/// - empty, truncated, non-JSON, or field-missing output → `false`;
/// - any report with a top-level `overall_ok: false` → `false`;
/// - an INCONSISTENT report — `overall_ok: true` alongside a non-empty
///   `drift_reasons` array — → `false` (every baseline probe derives
///   `overall_ok` from `drift_reasons.is_empty()`, so such a report is
///   self-contradictory evidence and must not green a stage);
/// - an `overall_ok` occurrence inside a string value or log line, with no
///   parseable report verdict, → `false` (a substring match would green on
///   exactly this output);
/// - otherwise, at least one `overall_ok: true` → `true`.
pub fn validator_report_ok(output: &str) -> bool {
    let mut saw_ok = false;
    for candidate in json_object_candidates(output) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(candidate) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(verdict) = object
            .get("overall_ok")
            .and_then(serde_json::Value::as_bool)
        else {
            continue;
        };
        if !verdict {
            return false;
        }
        let drifted = object
            .get("drift_reasons")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|reasons| !reasons.is_empty());
        if drifted {
            return false;
        }
        saw_ok = true;
    }
    saw_ok
}

/// Extract every balanced JSON object candidate from `output`, string-aware so
/// braces inside string values do not break the scan. Candidates that fail to
/// parse are ignored by the caller (fail closed), not by this function.
fn json_object_candidates(output: &str) -> Vec<&str> {
    let bytes = output.as_bytes();
    let mut candidates = Vec::new();
    // Only OUTERMOST objects are candidates: a nested `overall_ok` belongs to a
    // sub-report, not to the top-level verdict, and scanning it separately
    // would let `{"passed": true, "detail": {"overall_ok": true}}` green.
    let mut scan_from = 0usize;
    let mut start = scan_from;
    while start < bytes.len() {
        if bytes[start] != b'{' {
            start += 1;
            continue;
        }
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (offset, byte) in bytes[start..].iter().enumerate() {
            let b = *byte;
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        candidates.push(&output[start..=start + offset]);
                        scan_from = start + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        // Continue scanning AFTER the emitted candidate so nested objects are
        // never scanned as candidates of their own.
        start = scan_from.max(start + 1);
    }
    candidates
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
    use super::{
        ControlMasterTeardown, SHARED_HARDENING_O_FLAGS, base_scp_command, base_ssh_command,
        parse_status_field, parse_status_node_id, run_remote_retrying, validator_report_ok,
    };
    use crate::vm_lab::orchestrator::connection::NodeConnection;
    use crate::vm_lab::orchestrator::error::AdapterError;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn ssh_and_scp_share_the_full_connection_hardening_set() {
        // Both transports must carry the same security posture. This fails loudly
        // if a hardening `-o` flag ever drifts out of one builder but not the
        // other — the whole reason the shared helper exists.
        let id = Path::new("/tmp/id_ed25519");
        let kh = Path::new("/tmp/known_hosts");
        let (ssh_cmd, _teardown) = base_ssh_command("host.example", 22, Some("debian"), id, kh);
        let scp_cmd = base_scp_command(2222, id, kh, Some("debian"));
        for (label, args) in [("ssh", args_of(&ssh_cmd)), ("scp", args_of(&scp_cmd))] {
            assert!(
                args.iter().any(|a| a == "/dev/null"),
                "{label} must ignore system ssh_config (-F /dev/null): {args:?}"
            );
            for flag in SHARED_HARDENING_O_FLAGS {
                assert!(
                    args.iter().any(|a| a == flag),
                    "{label} missing shared hardening flag {flag}: {args:?}"
                );
            }
            assert!(
                args.iter().any(|a| a == "-i"),
                "{label} must pin the identity key: {args:?}"
            );
            assert!(
                args.iter().any(|a| a.starts_with("UserKnownHostsFile=")),
                "{label} must pin known-hosts: {args:?}"
            );
        }
    }

    #[test]
    fn ssh_and_scp_keep_their_protocol_specific_flags() {
        // The intended per-transport differences must survive the shared-helper
        // refactor: ssh uses `-p`/`-l`, scp uses `-P`/`-o User=`.
        let id = Path::new("/tmp/id_ed25519");
        let kh = Path::new("/tmp/known_hosts");
        let (ssh_cmd, _teardown) = base_ssh_command("host.example", 22, Some("debian"), id, kh);
        let ssh_args = args_of(&ssh_cmd);
        assert!(
            ssh_args.iter().any(|a| a == "-p"),
            "ssh uses -p: {ssh_args:?}"
        );
        let l_idx = ssh_args.iter().position(|a| a == "-l").expect("ssh -l");
        assert_eq!(ssh_args[l_idx + 1], "debian");

        let scp_cmd = base_scp_command(2222, id, kh, Some("debian"));
        let scp_args = args_of(&scp_cmd);
        assert!(
            scp_args.iter().any(|a| a == "-P"),
            "scp uses -P: {scp_args:?}"
        );
        assert!(
            scp_args.iter().any(|a| a == "User=debian"),
            "scp sets login via -o User=: {scp_args:?}"
        );
    }

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
    fn run_remote_retrying_exhausts_attempts_and_returns_last_error() {
        // Regression (ledger 2026-07-11): the OS-version probe must retry
        // transient SSH before degrading. Drive the retry loop against a
        // non-SSH connection so every attempt fails fast (ssh_params rejects it
        // with no network I/O and no sleep inside run_remote); zero backoff
        // keeps the test from sleeping while still exercising all attempts.
        let adb = NodeConnection::Adb {
            device_serial: "emulator-5554".to_owned(),
        };
        let err = run_remote_retrying(&adb, "printf hi", Duration::from_secs(1), 3, Duration::ZERO)
            .expect_err("non-SSH connection must fail every attempt");
        assert!(
            matches!(err, AdapterError::Ssh { .. }),
            "expected SSH-kind error from ssh_params rejection, got {err:?}"
        );
    }

    #[test]
    fn run_remote_retrying_clamps_zero_attempts_to_one() {
        // attempts=0 must still run exactly once and return an error rather than
        // silently succeeding or panicking.
        let adb = NodeConnection::Adb {
            device_serial: "emulator-5554".to_owned(),
        };
        assert!(
            run_remote_retrying(&adb, "printf hi", Duration::from_secs(1), 0, Duration::ZERO)
                .is_err(),
            "zero attempts clamps to one real attempt and still fails closed"
        );
    }

    #[test]
    fn parse_status_node_id_matches_generic_field_parser() {
        // parse_status_node_id delegates to parse_status_field so there is one
        // parsing implementation; lock that they agree, including the
        // not-present and prefix-collision cases.
        let status = "role=admin node_id=abc123 endpoint=1.2.3.4:51820";
        assert_eq!(parse_status_node_id(status), Some("abc123".to_owned()));
        assert_eq!(
            parse_status_node_id(status),
            parse_status_field(status, "node_id")
        );
        assert_eq!(parse_status_node_id("role=admin"), None);
        // A field whose name merely ends with node_id must not match.
        assert_eq!(parse_status_node_id("parent_node_id=zzz"), None);
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

    #[test]
    fn validator_report_ok_rejects_ok_report_with_nonempty_drift_reasons() {
        // QH-39 finding 2, drift-consistency half: `overall_ok: true` alongside
        // a non-empty `drift_reasons` is self-contradictory evidence — every
        // baseline probe derives `overall_ok` from `drift_reasons.is_empty()` —
        // so the report must not green a stage. Empty reasons stay green.
        assert!(!validator_report_ok(
            "{\n  \"overall_ok\": true,\n  \"drift_reasons\": [\"resolver drifted\"]\n}"
        ));
        assert!(validator_report_ok(
            "{\n  \"overall_ok\": true,\n  \"drift_reasons\": []\n}"
        ));
        // Absent field (e.g. the authenticode report carries no drift_reasons)
        // imposes no constraint.
        assert!(validator_report_ok("{\"overall_ok\": true}"));
    }

    #[test]
    fn validator_report_ok_ignores_verdict_shaped_text_outside_json() {
        // QH-39 finding 2, raw-substring half: the verdict must come from a
        // typed JSON report, not from any text that happens to contain the
        // substring. An occurrence inside a string value, a log line, or a
        // wrong-schema object is not a verdict.
        assert!(!validator_report_ok(
            r#"{"drift_reasons": ["note: \"overall_ok\": true observed in log"]}"#
        ));
        assert!(!validator_report_ok(r#"log line: "overall_ok": true"#));
        // Wrong-schema object that parses but has no top-level overall_ok.
        assert!(!validator_report_ok(
            r#"{"passed": true, "detail": {"overall_ok": true}}"#
        ));
    }

    #[test]
    fn validator_report_ok_rejects_truncated_report() {
        // A truncated report that merely CLAIMS ok must fail closed; the old
        // substring match greened on exactly this shape.
        assert!(!validator_report_ok("{\"overall_ok\": true, \"drift_re"));
    }

    #[test]
    fn validator_report_ok_reads_pretty_report_after_merged_stderr() {
        // The robustness the typed parser must keep: pretty-printed report with
        // a merged stderr line before AND after, plus braces in the log noise.
        assert!(validator_report_ok(
            "WARN {init} something\n{\n  \"overall_ok\": true,\n  \"drift_reasons\": []\n}\nbye"
        ));
    }
}

#[cfg(test)]
mod powershell_clixml_rendering_tests {
    use super::render_command_failure_detail;

    /// The shape that actually reached the ledger for CP-4 failures #2 and #3
    /// (`WindowsNodeBootstrapTriageVerdict_2026-08-28.md` §5): a CLIXML
    /// envelope whose `<S S="Error">` records carry the PowerShell error text
    /// with `_x000D__x000A_` line escapes.
    const CLIXML_STDERR: &str = concat!(
        "#< CLIXML\r\n",
        "<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">",
        "<S S=\"Error\">winget configure failed for RustyNet bootstrap configuration_x000D__x000A_</S>",
        "<S S=\"Error\">At line:1 char:149_x000D__x000A_</S>",
        "<S S=\"Error\">+ ... \\Rustynet&apos;; &amp; &apos;C:\\Windows\\Temp\\rustynet-stage\\Bootstrap ..._x000D__x000A_</S>",
        "</Objs>"
    );

    #[test]
    fn ssh_command_detail_surfaces_human_readable_powershell_error() {
        let detail = render_command_failure_detail(CLIXML_STDERR, "");
        assert!(
            detail.contains("[powershell error: "),
            "SSH-path rendering must decode CLIXML into a readable record; got: {detail}"
        );
        assert!(
            detail.contains("winget configure failed for RustyNet bootstrap configuration"),
            "the decoded record must carry the actual PowerShell error text; got: {detail}"
        );
        assert!(
            detail.contains("At line:1 char:149"),
            "every `<S>` record must be decoded, not just the first; got: {detail}"
        );
        assert!(
            !detail
                .split("[powershell error: ")
                .nth(1)
                .unwrap_or_default()
                .contains("_x000D_"),
            "the decoded record must not still carry CLIXML escapes; got: {detail}"
        );
        assert!(
            detail.contains("&") || detail.contains("';"),
            "XML entities must be decoded back to their characters; got: {detail}"
        );
    }

    #[test]
    fn ssh_command_detail_preserves_the_raw_clixml_alongside_the_decoded_record() {
        let detail = render_command_failure_detail(CLIXML_STDERR, "");
        // The Rust --node engine writes its per-stage log from this same
        // summary, so decoding must ADD the readable form, never replace the
        // raw one.
        assert!(
            detail.contains("<S S=\"Error\">"),
            "raw CLIXML must remain reachable in the rendered detail; got: {detail}"
        );
        let raw_at = detail.find("<S S=\"Error\">").expect("raw CLIXML present");
        let decoded_at = detail.find("[powershell error: ").expect("decoded present");
        assert!(
            raw_at < decoded_at,
            "the decoded record must come last so front-truncation cannot cut it"
        );
    }

    #[test]
    fn ssh_command_detail_leaves_non_clixml_stderr_untouched() {
        let plain = "bash: line 1: rustynetd: command not found";
        assert_eq!(render_command_failure_detail(plain, ""), plain);
    }

    #[test]
    fn ssh_command_detail_leaves_non_clixml_two_stream_output_untouched() {
        let detail = render_command_failure_detail("error: linker `cc` not found", "build failed");
        assert_eq!(
            detail,
            "error: linker `cc` not found\n[stdout: build failed]"
        );
        assert!(!detail.contains("[powershell error: "));
    }

    #[test]
    fn ssh_command_detail_decodes_a_clixml_record_that_arrived_on_stdout() {
        let detail = render_command_failure_detail(
            "",
            "#< CLIXML\r\n<Objs><S S=\"Error\">Configuration is not enabled._x000D__x000A_</S></Objs>",
        );
        assert!(
            detail.contains("Configuration is not enabled."),
            "stdout-carried CLIXML must decode too; got: {detail}"
        );
    }
}

#[cfg(test)]
mod remote_command_seam_tests {
    use super::*;

    #[test]
    fn from_validated_single_rejects_a_single_quoted_value_before_quoting() {
        let err = RemoteCommand::from_validated_single("target", "no'together")
            .expect_err("single quote must be refused");
        assert!(err.to_string().contains("target"));
    }

    #[test]
    fn from_validated_single_quotes_an_accepted_value() {
        let cmd = RemoteCommand::from_validated_single("target", "10.0.0.5")
            .expect("plain value must validate");
        assert_eq!(cmd.as_str(), "'10.0.0.5'");
    }

    #[test]
    fn from_args_never_produces_a_command_when_an_argument_is_rejected() {
        // The metacharacter-bearing value cannot become a ValidatedArg, so no
        // RemoteCommand is ever constructed — the rejection happens before any
        // command string exists.
        let rejected = ValidatedArg::ip("10.0.0.5; rm -rf /");
        assert!(rejected.is_err(), "metacharacters must fail the ip class");
        let err = rejected.expect_err("rejection expected").to_string();
        assert!(!err.contains("rm -rf"), "error must not echo the payload");
    }

    #[test]
    fn from_args_space_joins_shell_quoted_validated_values() {
        let args = [
            ValidatedArg::node_id("edge-1").expect("valid node id"),
            ValidatedArg::ip("10.0.0.5").expect("valid ip"),
            ValidatedArg::port("4242").expect("valid port"),
        ];
        let cmd = RemoteCommand::from_args("demo", &args).expect("all validated");
        assert_eq!(cmd.as_str(), "'edge-1' '10.0.0.5' '4242'");
    }

    #[test]
    fn from_args_refuses_an_empty_argument_list() {
        let err = RemoteCommand::from_args("demo", &[]).expect_err("empty is a bug");
        assert!(err.to_string().contains("demo"));
    }

    #[test]
    fn remote_command_debug_prints_length_only() {
        let cmd = RemoteCommand::from_validated_single("target", "secret-thing")
            .expect("plain value must validate");
        let rendered = format!("{cmd:?}");
        assert!(!rendered.contains("secret-thing"), "{rendered}");
        assert!(rendered.contains("len=14"), "{rendered}");
    }
}
