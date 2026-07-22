#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Cross-platform remote-shell abstraction for live-lab substages.
//!
//! Track B Phase 28 introduced this trait as the single hardened seam
//! between the live-lab substage code and per-OS shell-out paths; this
//! is the orchestrator-native copy (promoted out of the Linux-only bin
//! support tree) so the standard orchestrator's anchor/relay stages can
//! drive the same cross-OS primitives. It is a faithful copy of the
//! audited bin implementation; the only behavioural change is the
//! transport seam — [`transport_capture`] reuses the orchestrator's
//! hardened `adapter::ssh::run_remote` path (which the SSH-only
//! orchestrator already requires) instead of the bin's
//! `capture_remote_stdout` (which also carries a utmctl fallback the
//! orchestrator never needs). The body-generation, quoting, and audit
//! posture are byte-for-byte identical.
//!
//! Design constraints (per `CLAUDE.md` and `documents/SecurityMinimumBar.md`):
//!
//! * Argv-only exec for helpers — no shell construction with
//!   untrusted values. POSIX backends shell-escape each argv element
//!   with single quotes; the Windows backend wraps the entire command
//!   in PowerShell's `-EncodedCommand` form so the literal command
//!   bytes are transferred as base64-UTF16LE and never interpreted by
//!   any shell layer in between.
//! * Fail closed on every primitive. Empty paths, NUL-bearing argv
//!   tokens, and other ambiguous inputs return [`RemoteShellError`]
//!   instead of silently succeeding.
//! * Binary safety. `read_file` and `tcp_send_recv` round-trip raw
//!   bytes through base64 transport even on Windows, where the
//!   PowerShell pipeline mangles raw stdout by default. The ~33%
//!   overhead is acceptable for live-lab payloads (<1 MiB in practice).
//! * No plaintext secret on disk. Callers that need to push secret
//!   material can rely on `write_file`'s mode argument to constrain
//!   the on-disk ACL before any sensitive bytes are written; the
//!   POSIX backends chmod after the upload, the Windows backend
//!   tightens the ACL via `icacls` before the bytes are persisted.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::AdapterError;

// ── Public types ─────────────────────────────────────────────────────────────

/// Single-line file stat returned by [`RemoteShellHost::stat`].
///
/// `mode_octal` is Unix-style on POSIX backends; on Windows it is a
/// synthetic value computed from the SDDL ACL by [`WindowsShellHost`].
/// `owner_uid_or_sid` and `group_gid_or_sid` are numeric decimal uid/gid
/// strings on Unix and SDDL SID strings on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStat {
    pub size: u64,
    pub mode_octal: u16,
    pub owner_uid_or_sid: String,
    pub group_gid_or_sid: String,
}

/// Outcome of [`RemoteShellHost::run_argv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExitStatus {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl RemoteExitStatus {
    /// Convenience: returns `true` when the remote command exited with
    /// status zero. Live-lab substages frequently want to short-circuit
    /// on success without first destructuring `code`.
    pub fn is_success(&self) -> bool {
        self.code == 0
    }
}

/// Error variants returned by every primitive on the trait. The enum
/// is owned (no borrow lifetimes) so callers can `?` it through their
/// own `Result<_, String>` paths without lifetime gymnastics.
#[derive(Debug)]
pub enum RemoteShellError {
    /// The caller supplied an input the trait can prove is unsafe or
    /// ambiguous (empty path, NUL-bearing argv, etc.). The contract
    /// is: every backend MUST reject the same set of inputs the same
    /// way so substages stay portable.
    InvalidInput { message: String },
    /// The underlying transport (ssh / scp / nc) reported a failure.
    /// Includes both spawn errors and non-zero exit codes from the
    /// transport itself — not from the remote command. Use
    /// [`RemoteExitStatus::code`] to detect remote command failure.
    Transport { message: String },
    /// The remote host accepted the command but the response was
    /// malformed (unexpected base64, unparseable stat header, etc.).
    /// Distinct from Transport so the operator can see whether the
    /// failure is a transport-level issue or a server-side bug.
    Protocol { message: String },
    /// TCP send/recv failed (connect refused, timeout, etc.). Kept
    /// separate from Transport because callers frequently treat
    /// network reachability failures as a soft signal during
    /// chaos / fault-injection substages.
    Network { message: String },
    /// The trait deliberately refuses to implement the requested
    /// primitive for the active backend, with an explicit reason.
    /// Reserved for future capability gaps; current trait surface
    /// must be implemented by all three backends.
    Unsupported { message: String },
}

impl fmt::Display for RemoteShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { message } => write!(f, "invalid input: {message}"),
            Self::Transport { message } => write!(f, "transport error: {message}"),
            Self::Protocol { message } => write!(f, "protocol error: {message}"),
            Self::Network { message } => write!(f, "network error: {message}"),
            Self::Unsupported { message } => write!(f, "unsupported: {message}"),
        }
    }
}

impl std::error::Error for RemoteShellError {}

impl From<RemoteShellError> for String {
    fn from(err: RemoteShellError) -> Self {
        err.to_string()
    }
}

/// Cross-platform remote shell primitives. Implementations dispatch
/// to per-OS backends via [`new_remote_shell_host`]; substages must
/// never reach below the trait into platform-specific helpers.
pub trait RemoteShellHost: Send + Sync {
    /// Read the bytes of `remote_path` from the remote host. The bytes
    /// are transferred via base64 transport on every backend so binary
    /// payloads round-trip correctly even on Windows where PowerShell
    /// pipelines mangle raw stdout.
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError>;

    /// Write `bytes` to `remote_path`, then constrain the on-disk
    /// permissions to `mode_octal`. On POSIX backends `mode_octal` is
    /// the chmod value (e.g. `0o600`). On Windows the mode is mapped
    /// to an ACL: `0o600`/`0o700` → SYSTEM+Administrators full control;
    /// `0o644`/`0o755` → BUILTIN\Users read. Modes outside this set
    /// are rejected fail-closed to keep the surface narrow.
    fn write_file(
        &self,
        remote_path: &str,
        bytes: &[u8],
        mode_octal: u16,
    ) -> Result<(), RemoteShellError>;

    /// Stat `remote_path` and return canonical metadata. See
    /// [`RemoteStat`] for the cross-platform conventions.
    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError>;

    /// Run `argv` on the remote host with `env` extra environment
    /// variables and `stdin` as the process input. `argv` is treated
    /// as a literal argument vector — POSIX backends single-quote each
    /// element before forwarding to `sh -lc`; the Windows backend
    /// constructs a PowerShell `Start-Process -ArgumentList` array
    /// and forwards via `-EncodedCommand` so no shell layer
    /// interprets the elements.
    ///
    /// `argv[0]` is the program to run; the trait requires at least
    /// one element and rejects empty argv vectors. NUL bytes in any
    /// element are rejected fail-closed.
    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError>;

    /// Send `payload` to `addr` (host:port form) and return the
    /// server's response. `timeout` bounds the total operation. The
    /// POSIX backends use `nc -w <secs>`; the Windows backend uses
    /// `[System.Net.Sockets.TcpClient]` with explicit base64
    /// framing on both directions so binary payloads survive the
    /// PowerShell pipeline.
    fn tcp_send_recv(
        &self,
        addr: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteShellError>;
}

// ── Shared input validation ──────────────────────────────────────────────────

/// Centralised path-input check shared by every backend. Empty paths
/// and NUL bytes are rejected fail-closed so a misformed substage
/// never reaches the transport layer.
pub(crate) fn validate_remote_path(path: &str) -> Result<(), RemoteShellError> {
    if path.is_empty() {
        return Err(RemoteShellError::InvalidInput {
            message: "remote path must not be empty".to_owned(),
        });
    }
    if path.contains('\0') {
        return Err(RemoteShellError::InvalidInput {
            message: "remote path must not contain NUL bytes".to_owned(),
        });
    }
    Ok(())
}

/// Centralised argv-element check. Rejects empty argv vectors, NUL
/// bytes in any element, and an empty `argv[0]` (the program slot).
pub(crate) fn validate_argv(argv: &[&str]) -> Result<(), RemoteShellError> {
    if argv.is_empty() {
        return Err(RemoteShellError::InvalidInput {
            message: "argv must contain at least the program name".to_owned(),
        });
    }
    if argv[0].is_empty() {
        return Err(RemoteShellError::InvalidInput {
            message: "argv[0] (program) must not be empty".to_owned(),
        });
    }
    for (index, element) in argv.iter().enumerate() {
        if element.contains('\0') {
            return Err(RemoteShellError::InvalidInput {
                message: format!("argv element {index} must not contain NUL bytes"),
            });
        }
    }
    Ok(())
}

/// Centralised env-pair check. Rejects empty key, NUL bytes, '=' in
/// the key, and newlines in the value.
pub(crate) fn validate_env(env: &[(&str, &str)]) -> Result<(), RemoteShellError> {
    for (index, (key, value)) in env.iter().enumerate() {
        if key.is_empty() {
            return Err(RemoteShellError::InvalidInput {
                message: format!("env pair {index} has empty key"),
            });
        }
        if key.contains('=') || key.contains('\0') {
            return Err(RemoteShellError::InvalidInput {
                message: format!("env pair {index} key {key:?} must not contain '=' or NUL bytes"),
            });
        }
        if value.contains('\0') {
            return Err(RemoteShellError::InvalidInput {
                message: format!("env pair {index} value must not contain NUL bytes"),
            });
        }
    }
    Ok(())
}

/// Centralised TCP-address check. `addr` MUST be in `host:port` form.
/// Empty host, empty port, and out-of-range port are all rejected.
pub(crate) fn validate_tcp_addr(addr: &str) -> Result<(&str, u16), RemoteShellError> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| RemoteShellError::InvalidInput {
            message: format!("tcp address {addr:?} missing ':' separator"),
        })?;
    if host.is_empty() {
        return Err(RemoteShellError::InvalidInput {
            message: format!("tcp address {addr:?} has empty host"),
        });
    }
    let port: u16 = port_str
        .parse()
        .map_err(|err| RemoteShellError::InvalidInput {
            message: format!("tcp address {addr:?} port parse failed: {err}"),
        })?;
    if port == 0 {
        return Err(RemoteShellError::InvalidInput {
            message: format!("tcp address {addr:?} port must be non-zero"),
        });
    }
    if host.contains('\0') {
        return Err(RemoteShellError::InvalidInput {
            message: format!("tcp address {addr:?} host must not contain NUL bytes"),
        });
    }
    Ok((host, port))
}

/// Allow-list of mode octals the cross-platform mode → ACL mapping
/// recognises. Restricting to the live-lab's actual modes makes the
/// Windows ACL translation auditable: there are exactly four target
/// ACL shapes.
pub(crate) fn validate_mode_octal(mode: u16) -> Result<(), RemoteShellError> {
    match mode {
        0o600 | 0o700 | 0o644 | 0o755 => Ok(()),
        other => Err(RemoteShellError::InvalidInput {
            message: format!(
                "mode_octal {other:o} not in cross-platform allow-list \
                 (allowed: 0o600, 0o700, 0o644, 0o755)"
            ),
        }),
    }
}

// ── Backend selection ────────────────────────────────────────────────────────

/// Return the per-OS backend appropriate for `platform`. The trait
/// object is `Arc` so substages can clone and share it across helper
/// closures without forcing each helper to re-thread identity/known-hosts
/// arguments through the call tree.
pub fn new_remote_shell_host(
    platform: VmGuestPlatform,
    conn: NodeConnection,
) -> Result<Arc<dyn RemoteShellHost>, AdapterError> {
    match platform {
        VmGuestPlatform::Linux => Ok(Arc::new(LinuxShellHost::new(conn))),
        VmGuestPlatform::Macos => Ok(Arc::new(MacosShellHost::new(conn))),
        VmGuestPlatform::Windows => Ok(Arc::new(WindowsShellHost::new(conn))),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(AdapterError::UnsupportedPlatform {
            platform,
            message: "remote shell host is only implemented for Linux, macOS, and Windows"
                .to_owned(),
        }),
    }
}

/// Transport timeout for a single remote shell operation. Generous so a
/// slow-but-valid remote command (enrollment mint, bundle pull) is not
/// killed mid-flight, while still bounding a hung session — the
/// bin-support `capture_remote_stdout` path had no overall command
/// timeout at all, so this is strictly tighter, not looser.
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(180);

/// Run `body` over SSH on `conn` and capture trimmed stdout. This is the
/// orchestrator-native transport seam: it reuses the hardened
/// [`ssh::run_remote`] path (StrictHostKeyChecking, IdentitiesOnly,
/// connection multiplexing, overall timeout) rather than the bin-support
/// `capture_remote_stdout` (which carries a utmctl fallback the SSH-only
/// orchestrator never needs). The error is surfaced as a `String` so the
/// copied body-gen `.map_err(|err| …{err})` sites stay byte-for-byte
/// identical to the audited bin implementation.
fn transport_capture(conn: &NodeConnection, body: &str) -> Result<String, String> {
    ssh::run_remote(conn, body, TRANSPORT_TIMEOUT).map_err(|err| err.to_string())
}

/// POSIX single-quote shell escape: each `'` becomes `'\''`. A verbatim
/// copy of the bin-support `shell_quote` so the copied POSIX body-gen
/// escapes argv elements and paths identically. The returned value
/// already includes the surrounding single quotes.
fn shell_quote(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ── Linux backend ────────────────────────────────────────────────────────────

/// Linux backend: argv passed via single-quoted `sh -lc` payload to
/// match the pre-Phase-28 behaviour exactly. Drives the orchestrator's
/// hardened SSH transport via [`transport_capture`].
pub struct LinuxShellHost {
    conn: NodeConnection,
}

impl LinuxShellHost {
    pub fn new(conn: NodeConnection) -> Self {
        Self { conn }
    }
}

impl RemoteShellHost for LinuxShellHost {
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
        posix_read_file(&self.conn, remote_path)
    }

    fn write_file(
        &self,
        remote_path: &str,
        bytes: &[u8],
        mode_octal: u16,
    ) -> Result<(), RemoteShellError> {
        posix_write_file(&self.conn, remote_path, bytes, mode_octal)
    }

    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
        posix_stat(&self.conn, remote_path, PosixStatDialect::Gnu)
    }

    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError> {
        posix_run_argv(&self.conn, argv, env, stdin)
    }

    fn tcp_send_recv(
        &self,
        addr: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteShellError> {
        posix_tcp_send_recv(&self.conn, addr, payload, timeout)
    }
}

// ── macOS backend ────────────────────────────────────────────────────────────

/// macOS backend: identical to Linux except `stat(1)` uses the BSD
/// `-f` format string rather than the GNU `-c` format. macOS ships
/// the BSD stat in `/usr/bin/stat`; the format strings are not
/// compatible.
pub struct MacosShellHost {
    conn: NodeConnection,
}

impl MacosShellHost {
    pub fn new(conn: NodeConnection) -> Self {
        Self { conn }
    }
}

impl RemoteShellHost for MacosShellHost {
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
        posix_read_file(&self.conn, remote_path)
    }

    fn write_file(
        &self,
        remote_path: &str,
        bytes: &[u8],
        mode_octal: u16,
    ) -> Result<(), RemoteShellError> {
        posix_write_file(&self.conn, remote_path, bytes, mode_octal)
    }

    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
        posix_stat(&self.conn, remote_path, PosixStatDialect::Bsd)
    }

    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError> {
        posix_run_argv(&self.conn, argv, env, stdin)
    }

    fn tcp_send_recv(
        &self,
        addr: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteShellError> {
        posix_tcp_send_recv(&self.conn, addr, payload, timeout)
    }
}

// ── Windows backend ──────────────────────────────────────────────────────────

/// Windows backend: PowerShell over OpenSSH using `-EncodedCommand`
/// so no shell layer interprets the command bytes. All binary payloads
/// (read_file, tcp_send_recv) are base64-framed on both directions to
/// survive the PowerShell pipeline, which mangles raw stdout by default.
pub struct WindowsShellHost {
    conn: NodeConnection,
}

impl WindowsShellHost {
    pub fn new(conn: NodeConnection) -> Self {
        Self { conn }
    }
}

impl RemoteShellHost for WindowsShellHost {
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
        validate_remote_path(remote_path)?;
        // PowerShell pipelines mangle binary stdout, so the script
        // base64-encodes the file server-side and we decode locally.
        // [Convert]::ToBase64String emits no whitespace so the trip
        // through SSH is a single contiguous line we can decode
        // verbatim.
        let script = format!(
            "$ErrorActionPreference='Stop'; $bytes = [System.IO.File]::ReadAllBytes('{}'); \
             [Console]::Out.Write([Convert]::ToBase64String($bytes))",
            powershell_single_quote_escape(remote_path)
        );
        let output = windows_run_powershell(&self.conn, &script, &[])?;
        decode_base64_strict(output.trim()).map_err(|err| RemoteShellError::Protocol {
            message: format!("read_file base64 decode failed for {remote_path}: {err}"),
        })
    }

    fn write_file(
        &self,
        remote_path: &str,
        bytes: &[u8],
        mode_octal: u16,
    ) -> Result<(), RemoteShellError> {
        validate_remote_path(remote_path)?;
        validate_mode_octal(mode_octal)?;
        let script = windows_write_file_script(remote_path, bytes, mode_octal);
        let _ = windows_run_powershell(&self.conn, &script, &[])?;
        Ok(())
    }

    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
        validate_remote_path(remote_path)?;
        // Emit a single canonical envelope so the parser does not need
        // to sift through PowerShell's pretty-printed object output.
        // `Get-Acl` exposes the SDDL (owner SID + DACL) and a
        // primary-group SID lookup. `(Get-Item).Length` is the file
        // size. The `OWNER:` / `GROUP:` prefixes let the parser
        // distinguish them despite the SID strings themselves
        // containing dashes and similar punctuation.
        let script = format!(
            "$ErrorActionPreference='Stop'; $p = '{}'; \
             $info = Get-Item -LiteralPath $p; \
             $acl = Get-Acl -LiteralPath $p; \
             $sddl = $acl.GetSecurityDescriptorSddlForm('All'); \
             $owner = $acl.Owner; \
             $group = $acl.Group; \
             if (-not $group) {{ $group = $owner; }}; \
             [Console]::Out.Write(\"SIZE:$($info.Length)`nOWNER:$owner`nGROUP:$group`nSDDL:$sddl`n\")",
            powershell_single_quote_escape(remote_path)
        );
        let output = windows_run_powershell(&self.conn, &script, &[])?;
        parse_windows_stat(&output)
    }

    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError> {
        validate_argv(argv)?;
        validate_env(env)?;
        // We assemble the array from single-quoted strings — base64 is
        // fine inside single quotes because PowerShell only treats `'`
        // as the terminator and we double any embedded `'` per the
        // standard PowerShell escape rule.
        let mut quoted: Vec<String> = Vec::with_capacity(argv.len());
        for arg in argv {
            quoted.push(format!("'{}'", powershell_single_quote_escape(arg)));
        }
        let arg_list = quoted.join(",");
        let env_setup = env
            .iter()
            .map(|(k, v)| {
                format!(
                    "[Environment]::SetEnvironmentVariable('{}','{}','Process'); ",
                    powershell_single_quote_escape(k),
                    powershell_single_quote_escape(v),
                )
            })
            .collect::<String>();
        let stdin_b64 = encode_base64_standard(stdin);
        // Pipe stdin in via a temporary file — Start-Process's
        // -RedirectStandardInput only accepts a path, and a temp
        // file is the only portable way to feed binary stdin without
        // teeing through a pipe that PowerShell would mangle. The
        // temp files are unlinked at the end inside a finally block
        // so a failure mid-script does not leak material on disk.
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             {env_setup}\
             $stdinBytes = [Convert]::FromBase64String('{stdin_b64}'); \
             $stdinPath = [System.IO.Path]::Combine($env:TEMP, [System.IO.Path]::GetRandomFileName()); \
             [System.IO.File]::WriteAllBytes($stdinPath, $stdinBytes); \
             $stdoutPath = [System.IO.Path]::Combine($env:TEMP, [System.IO.Path]::GetRandomFileName()); \
             $stderrPath = [System.IO.Path]::Combine($env:TEMP, [System.IO.Path]::GetRandomFileName()); \
             try {{ \
               $argList = @({arg_list}); \
               if ($argList.Length -gt 1) {{ \
                 $proc = Start-Process -FilePath $argList[0] -ArgumentList $argList[1..($argList.Length-1)] \
                   -RedirectStandardInput $stdinPath -RedirectStandardOutput $stdoutPath \
                   -RedirectStandardError $stderrPath -NoNewWindow -Wait -PassThru; \
               }} else {{ \
                 $proc = Start-Process -FilePath $argList[0] \
                   -RedirectStandardInput $stdinPath -RedirectStandardOutput $stdoutPath \
                   -RedirectStandardError $stderrPath -NoNewWindow -Wait -PassThru; \
               }}; \
               $stdoutBytes = [System.IO.File]::ReadAllBytes($stdoutPath); \
               $stderrBytes = [System.IO.File]::ReadAllBytes($stderrPath); \
               [Console]::Out.Write(\"CODE:$($proc.ExitCode)`nSTDOUT:\"); \
               [Console]::Out.Write([Convert]::ToBase64String($stdoutBytes)); \
               [Console]::Out.Write(\"`nSTDERR:\"); \
               [Console]::Out.Write([Convert]::ToBase64String($stderrBytes)); \
               [Console]::Out.Write(\"`n\"); \
             }} finally {{ \
               Remove-Item -LiteralPath $stdinPath -Force -ErrorAction SilentlyContinue; \
               Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue; \
               Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue; \
             }}",
        );
        let output = windows_run_powershell(&self.conn, &script, &[])?;
        parse_windows_run_argv(&output)
    }

    fn tcp_send_recv(
        &self,
        addr: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteShellError> {
        let (host, port) = validate_tcp_addr(addr)?;
        let payload_b64 = encode_base64_standard(payload);
        let timeout_ms =
            u32::try_from(timeout.as_millis()).map_err(|_| RemoteShellError::InvalidInput {
                message: format!("tcp timeout {timeout:?} exceeds 32-bit milliseconds"),
            })?;
        let script = windows_tcp_send_recv_script(host, port, &payload_b64, timeout_ms);
        let output = windows_run_powershell(&self.conn, &script, &[]).map_err(|err| {
            RemoteShellError::Network {
                message: format!("tcp_send_recv to {addr} failed: {err}"),
            }
        })?;
        decode_base64_strict(output.trim()).map_err(|err| RemoteShellError::Protocol {
            message: format!("tcp_send_recv base64 decode failed for {addr}: {err}"),
        })
    }
}

// ── POSIX shared implementation ──────────────────────────────────────────────

/// Variant selector for the POSIX stat backend. GNU stat (Linux) and
/// BSD stat (macOS) use incompatible format strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PosixStatDialect {
    Gnu,
    Bsd,
}

fn posix_read_file(conn: &NodeConnection, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
    validate_remote_path(remote_path)?;
    // base64 the bytes server-side so the SSH transport sees only
    // text. `sudo -n cat` ensures we can read root-only files; the
    // POSIX `base64` tool is in coreutils on Linux and ships in
    // /usr/bin on macOS by default.
    let body = format!(
        "sudo -n cat -- {} | base64 | tr -d '\\n\\r '",
        shell_quote(remote_path)
    );
    let stdout =
        transport_capture(conn, body.as_str()).map_err(|err| RemoteShellError::Transport {
            message: format!("read_file ssh transport failed for {remote_path}: {err}"),
        })?;
    decode_base64_strict(stdout.trim()).map_err(|err| RemoteShellError::Protocol {
        message: format!("read_file base64 decode failed for {remote_path}: {err}"),
    })
}

fn posix_write_file(
    conn: &NodeConnection,
    remote_path: &str,
    bytes: &[u8],
    mode_octal: u16,
) -> Result<(), RemoteShellError> {
    validate_remote_path(remote_path)?;
    validate_mode_octal(mode_octal)?;
    let b64 = encode_base64_standard(bytes);
    // Decode to a temp file in /tmp (world-writable, no sudo needed for
    // mktemp), then `sudo -n install` atomically copies+modes it to the
    // final destination (which may be in a root-owned directory created
    // by ensure_remote_dir via run_argv/sudo). Using a destination-local
    // template for mktemp would fail when the parent dir is root-owned 700.
    let body = format!(
        "umask 077; \
         tmp=$(mktemp); \
         trap 'rm -f -- \"$tmp\"' EXIT; \
         printf %s {b64_quoted} | base64 -d > \"$tmp\"; \
         sudo -n install -m {mode:o} -- \"$tmp\" {dst}",
        b64_quoted = shell_quote(&b64),
        mode = mode_octal,
        dst = shell_quote(remote_path),
    );
    transport_capture(conn, body.as_str()).map_err(|err| RemoteShellError::Transport {
        message: format!("write_file ssh transport failed for {remote_path}: {err}"),
    })?;
    Ok(())
}

fn posix_stat(
    conn: &NodeConnection,
    remote_path: &str,
    dialect: PosixStatDialect,
) -> Result<RemoteStat, RemoteShellError> {
    validate_remote_path(remote_path)?;
    let format_arg = match dialect {
        PosixStatDialect::Gnu => "-c %s %a %u %g",
        PosixStatDialect::Bsd => "-f %z %Lp %u %g",
    };
    let body = format!(
        "sudo -n stat {fmt} -- {path}",
        fmt = format_arg,
        path = shell_quote(remote_path),
    );
    let stdout =
        transport_capture(conn, body.as_str()).map_err(|err| RemoteShellError::Transport {
            message: format!("stat ssh transport failed for {remote_path}: {err}"),
        })?;
    parse_posix_stat(stdout.trim())
}

fn posix_run_argv(
    conn: &NodeConnection,
    argv: &[&str],
    env: &[(&str, &str)],
    stdin: &[u8],
) -> Result<RemoteExitStatus, RemoteShellError> {
    validate_argv(argv)?;
    validate_env(env)?;
    let argv_quoted: Vec<String> = argv.iter().map(|s| shell_quote(s)).collect();
    let argv_line = argv_quoted.join(" ");
    let env_prefix = if env.is_empty() {
        String::new()
    } else {
        let mut parts = Vec::with_capacity(env.len());
        for (key, value) in env {
            parts.push(format!("{}={}", key, shell_quote(value)));
        }
        format!("env {} ", parts.join(" "))
    };
    let stdin_b64 = encode_base64_standard(stdin);
    // Wrap stdin via a base64 here-payload so binary payloads survive
    // the SSH session unmangled. The captured stdout/stderr go through
    // base64 too, with explicit `CODE:` / `STDOUT:` / `STDERR:`
    // sentinels so the parser is unambiguous even when the underlying
    // program emits matching strings of its own.
    let body = format!(
        "set +e; \
         stdin_tmp=$(mktemp); \
         stdout_tmp=$(mktemp); \
         stderr_tmp=$(mktemp); \
         trap 'rm -f -- \"$stdin_tmp\" \"$stdout_tmp\" \"$stderr_tmp\"' EXIT; \
         printf %s {stdin_b64_quoted} | base64 -d > \"$stdin_tmp\"; \
         sudo -n {env_prefix}{argv_line} <\"$stdin_tmp\" >\"$stdout_tmp\" 2>\"$stderr_tmp\"; \
         rc=$?; \
         printf 'CODE:%d\\n' \"$rc\"; \
         printf 'STDOUT:'; base64 < \"$stdout_tmp\" | tr -d '\\n\\r '; printf '\\n'; \
         printf 'STDERR:'; base64 < \"$stderr_tmp\" | tr -d '\\n\\r '; printf '\\n'",
        stdin_b64_quoted = shell_quote(&stdin_b64),
    );
    let stdout =
        transport_capture(conn, body.as_str()).map_err(|err| RemoteShellError::Transport {
            message: format!("run_argv ssh transport failed for {argv:?}: {err}"),
        })?;
    parse_run_argv_envelope(&stdout)
}

/// Remote shell body for a TCP send-recv probe. Prefers `nc` (the historical
/// path, unchanged), and falls back to bash's `/dev/tcp` when nc is absent so
/// the probe works on minimal guests — e.g. Rocky/RHEL, which ship no `nc` and
/// have no egress to `dnf install` one. The callers' requests are
/// newline-delimited (the server responds on the delimiter), so the reply
/// arrives without a TCP half-close — which `cat >&3; cat <&3` over `/dev/tcp`
/// does not perform but does not need here. `timeout` bounds the read exactly
/// as `nc -w` does. `host` is single-quote-escaped and `port` is a validated
/// u16, so neither can break out of the command.
fn build_tcp_send_recv_body(host: &str, port: u16, payload_b64: &str, timeout_secs: u64) -> String {
    let payload_b64_quoted = shell_quote(payload_b64);
    let host_quoted = shell_quote(host);
    format!(
        "if command -v nc >/dev/null 2>&1; then \
         printf %s {payload_b64_quoted} | base64 -d | nc -w {timeout_secs} -- {host_quoted} {port} | base64 | tr -d '\\n\\r '; \
         elif command -v bash >/dev/null 2>&1; then \
         printf %s {payload_b64_quoted} | base64 -d | timeout {timeout_secs} bash -c 'exec 3<>/dev/tcp/'{host_quoted}'/'{port}' || exit 1; cat >&3; cat <&3' | base64 | tr -d '\\n\\r '; \
         else echo 'tcp probe needs nc or bash; neither found' >&2; exit 127; fi"
    )
}

fn posix_tcp_send_recv(
    conn: &NodeConnection,
    addr: &str,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, RemoteShellError> {
    let (host, port) = validate_tcp_addr(addr)?;
    let timeout_secs = std::cmp::max(1, timeout.as_secs());
    let payload_b64 = encode_base64_standard(payload);
    let body = build_tcp_send_recv_body(host, port, &payload_b64, timeout_secs);
    let stdout =
        transport_capture(conn, body.as_str()).map_err(|err| RemoteShellError::Network {
            message: format!("tcp_send_recv to {addr} failed: {err}"),
        })?;
    decode_base64_strict(stdout.trim()).map_err(|err| RemoteShellError::Protocol {
        message: format!("tcp_send_recv base64 decode failed for {addr}: {err}"),
    })
}

// ── Windows shared helpers ───────────────────────────────────────────────────

fn windows_run_powershell(
    conn: &NodeConnection,
    script: &str,
    _env: &[(&str, &str)],
) -> Result<String, RemoteShellError> {
    // EncodedCommand requires UTF-16LE bytes, base64 encoded. This
    // avoids every shell-quoting concern between the local SSH client
    // and the remote PowerShell — PowerShell decodes the payload
    // verbatim before parsing it.
    let utf16_bytes = utf16le_bytes(script);
    let encoded = encode_base64_standard(&utf16_bytes);
    let command = format!("powershell -NoProfile -NonInteractive -EncodedCommand {encoded}");
    transport_capture(conn, command.as_str()).map_err(|err| RemoteShellError::Transport {
        message: format!("powershell transport failed: {err}"),
    })
}

/// Build the PowerShell body that drives the Windows `write_file`
/// primitive. Extracted from [`WindowsShellHost::write_file`] so a
/// unit test can assert the atomic-create-with-restrictive-ACL
/// ordering without needing a remote PowerShell to actually execute
/// it.
///
/// The script's hardened contract (mirrors POSIX `umask 077; install
/// -m`):
///
///   1. Create an empty tmpfile in the target's parent dir.
///   2. Tighten the tmpfile's ACL BEFORE any secret bytes are
///      written. The first `WriteAllBytes` happens only after the
///      DACL is canonical, so a concurrent observer that opens the
///      tmpfile during the race window sees an empty file it has no
///      read access to.
///   3. `WriteAllBytes` the payload into the already-ACL'd tmpfile.
///   4. `Move-Item` the tmpfile onto the final path. NTFS rename
///      preserves the source DACL on the destination, so the target
///      inherits the SYSTEM+Administrators-only ACL we just
///      installed.
///   5. Verify the post-move DACL matches the requested mode. If
///      verification fails the file is deleted and the script
///      throws fail-closed.
///
/// This keeps the invariant: between the moment any byte of the
/// final path exists and the moment its DACL is locked down, NO
/// secret bytes can have been written.
pub(crate) fn windows_write_file_script(remote_path: &str, bytes: &[u8], mode: u16) -> String {
    let b64 = encode_base64_standard(bytes);
    let acl_script = windows_mode_to_acl_script_for_tmpfile(mode);
    let post_move_verify = windows_post_move_acl_verify_script(mode);
    format!(
        "$ErrorActionPreference='Stop'; $path = '{path}'; \
         $parent = Split-Path -Parent $path; \
         if ($parent -and -not (Test-Path -LiteralPath $parent)) {{ \
           New-Item -ItemType Directory -Force -Path $parent | Out-Null; \
         }}; \
         $tmpName = [System.IO.Path]::GetRandomFileName(); \
         $tmp = if ($parent) {{ Join-Path -Path $parent -ChildPath ($tmpName + '.partial') }} \
                else {{ $tmpName + '.partial' }}; \
         try {{ \
           $null = New-Item -ItemType File -Path $tmp -Force; \
           {acl_script}; \
           [System.IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String('{b64}')); \
           Move-Item -LiteralPath $tmp -Destination $path -Force; \
           {post_move_verify}; \
         }} catch {{ \
           if (Test-Path -LiteralPath $tmp) {{ \
             Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; \
           }}; \
           throw; \
         }}",
        path = powershell_single_quote_escape(remote_path),
    )
}

/// Build the PowerShell body that drives the Windows TCP send/recv
/// primitive. Extracted from [`WindowsShellHost::tcp_send_recv`] so a
/// unit test can assert the script structure without needing a remote
/// PowerShell to actually execute it.
///
/// The read loop MUST be timeout-based, not first-segment-arrival-
/// based: keep reading until either the peer closes (Read returns 0)
/// or the caller's deadline fires. This matches POSIX `nc -w <secs>`.
pub(crate) fn windows_tcp_send_recv_script(
    host: &str,
    port: u16,
    payload_b64: &str,
    timeout_ms: u32,
) -> String {
    format!(
        "$ErrorActionPreference='Stop'; \
         $client = New-Object System.Net.Sockets.TcpClient; \
         $client.ReceiveTimeout = {timeout_ms}; \
         $client.SendTimeout = {timeout_ms}; \
         try {{ \
           $iar = $client.BeginConnect('{host}', {port}, $null, $null); \
           if (-not $iar.AsyncWaitHandle.WaitOne({timeout_ms}, $false)) {{ \
             throw 'tcp connect timed out'; \
           }}; \
           $client.EndConnect($iar); \
           $stream = $client.GetStream(); \
           $payload = [Convert]::FromBase64String('{payload_b64}'); \
           if ($payload.Length -gt 0) {{ $stream.Write($payload, 0, $payload.Length); }}; \
           $stream.Flush(); \
           $buffer = New-Object byte[] 4096; \
           $ms = New-Object System.IO.MemoryStream; \
           $deadline = [DateTime]::UtcNow.AddMilliseconds({timeout_ms}); \
           while ([DateTime]::UtcNow -lt $deadline) {{ \
             $remainingMs = [int]([Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)); \
             if ($remainingMs -le 0) {{ break; }}; \
             $readAr = $stream.BeginRead($buffer, 0, $buffer.Length, $null, $null); \
             if (-not $readAr.AsyncWaitHandle.WaitOne($remainingMs, $false)) {{ \
               try {{ $stream.Close(); }} catch {{}}; \
               break; \
             }}; \
             try {{ \
               $read = $stream.EndRead($readAr); \
             }} catch {{ \
               break; \
             }}; \
             if ($read -le 0) {{ break; }}; \
             $ms.Write($buffer, 0, $read); \
           }}; \
           $bytes = $ms.ToArray(); \
           [Console]::Out.Write([Convert]::ToBase64String($bytes)); \
         }} finally {{ \
           $client.Close(); \
         }}",
        host = powershell_single_quote_escape(host),
    )
}

fn windows_mode_to_acl_script(remote_path: &str, mode: u16) -> String {
    let quoted = powershell_single_quote_escape(remote_path);
    match mode {
        0o600 | 0o700 => {
            // Owner-only: SYSTEM + Administrators full control, no
            // other entries. Use `icacls /inheritance:r /grant:r` so
            // any pre-existing entries from a permissive parent are
            // dropped before the new entries are applied.
            format!(
                "& icacls '{quoted}' /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' | Out-Null"
            )
        }
        0o644 | 0o755 => {
            // World-readable: SYSTEM + Administrators full control,
            // BUILTIN\\Users read. The exec bit in 0o755 maps to a
            // no-op on Windows (NTFS does not have a portable
            // executable bit); the SDDL is identical to 0o644 in
            // practice.
            format!(
                "& icacls '{quoted}' /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' /grant:r 'BUILTIN\\Users:(R)' | Out-Null"
            )
        }
        _ => format!("Write-Error 'mode {mode:o} not in cross-platform allow-list'; exit 1"),
    }
}

/// Tmpfile-targeted variant of [`windows_mode_to_acl_script`]. The
/// `write_file` PowerShell body holds the tmpfile path in a
/// `$tmp` variable rather than a baked-in string literal so the
/// random suffix is constructed remote-side. Emitting `& icacls $tmp`
/// (no surrounding single quotes) lets PowerShell expand the variable
/// before invoking icacls.
///
/// The DACL shape matches the path-literal variant exactly so the
/// post-move file inherits the same SDDL contract.
pub(crate) fn windows_mode_to_acl_script_for_tmpfile(mode: u16) -> String {
    match mode {
        0o600 | 0o700 => {
            "& icacls $tmp /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' | Out-Null".to_owned()
        }
        0o644 | 0o755 => {
            "& icacls $tmp /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' /grant:r 'BUILTIN\\Users:(R)' | Out-Null".to_owned()
        }
        _ => format!("Write-Error 'mode {mode:o} not in cross-platform allow-list'; exit 1"),
    }
}

/// Post-move DACL verification snippet. Reads the SDDL from the final
/// `$path` and confirms it matches the expected shape for the
/// requested mode. On drift the file is removed and the script
/// throws, so a caller never sees a "success" return when the
/// post-rename ACL diverges from the requested mode.
///
/// The regex matches the SDDL DACL produced by `icacls /inheritance:r
/// /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' [...]'`:
///   * Owner-only (0o600 / 0o700) — `D:PAI(A;;FA;;;SY)(A;;FA;;;BA)` or
///     the no-AI variant. `WD` (Everyone) and `BU` (BUILTIN\Users) MUST
///     NOT appear.
///   * World-readable (0o644 / 0o755) — same as above plus
///     `(A;;...;;;BU)` MAY appear. `WD` MUST NOT.
pub(crate) fn windows_post_move_acl_verify_script(mode: u16) -> String {
    match mode {
        0o600 | 0o700 => {
            "$verifyAcl = (Get-Acl -LiteralPath $path).Sddl; \
             if ($verifyAcl -match ';WD\\)' -or $verifyAcl -match ';BU\\)') { \
               Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; \
               throw 'rustynet-write-file: post-move ACL drift on owner-only mode (Users or Everyone present)'; \
             }; \
             if (-not ($verifyAcl -match ';FA;;;SY\\)') -or -not ($verifyAcl -match ';FA;;;BA\\)')) { \
               Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; \
               throw 'rustynet-write-file: post-move ACL drift on owner-only mode (SYSTEM or Administrators missing)'; \
             }".to_owned()
        }
        0o644 | 0o755 => {
            "$verifyAcl = (Get-Acl -LiteralPath $path).Sddl; \
             if ($verifyAcl -match ';WD\\)') { \
               Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; \
               throw 'rustynet-write-file: post-move ACL drift on world-readable mode (Everyone present)'; \
             }; \
             if (-not ($verifyAcl -match ';FA;;;SY\\)') -or -not ($verifyAcl -match ';FA;;;BA\\)')) { \
               Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; \
               throw 'rustynet-write-file: post-move ACL drift on world-readable mode (SYSTEM or Administrators missing)'; \
             }".to_owned()
        }
        _ => format!(
            "Write-Error 'mode {mode:o} not in cross-platform allow-list for post-move verify'; exit 1"
        ),
    }
}

// ── Parsers ──────────────────────────────────────────────────────────────────

pub(crate) fn parse_posix_stat(line: &str) -> Result<RemoteStat, RemoteShellError> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() != 4 {
        return Err(RemoteShellError::Protocol {
            message: format!(
                "posix stat output {line:?} expected 4 fields, got {}",
                fields.len()
            ),
        });
    }
    let size: u64 = fields[0]
        .parse()
        .map_err(|err| RemoteShellError::Protocol {
            message: format!("posix stat size {:?} parse failed: {err}", fields[0]),
        })?;
    let mode_octal =
        u16::from_str_radix(fields[1], 8).map_err(|err| RemoteShellError::Protocol {
            message: format!("posix stat mode {:?} parse failed: {err}", fields[1]),
        })?;
    Ok(RemoteStat {
        size,
        mode_octal,
        owner_uid_or_sid: fields[2].to_owned(),
        group_gid_or_sid: fields[3].to_owned(),
    })
}

pub(crate) fn parse_windows_stat(text: &str) -> Result<RemoteStat, RemoteShellError> {
    let mut size: Option<u64> = None;
    let mut owner: Option<String> = None;
    let mut group: Option<String> = None;
    let mut sddl: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("SIZE:") {
            size = Some(
                rest.trim()
                    .parse()
                    .map_err(|err| RemoteShellError::Protocol {
                        message: format!("windows stat SIZE {rest:?} parse failed: {err}"),
                    })?,
            );
        } else if let Some(rest) = line.strip_prefix("OWNER:") {
            owner = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("GROUP:") {
            group = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("SDDL:") {
            sddl = Some(rest.trim().to_owned());
        }
    }
    let size = size.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("windows stat missing SIZE line in {text:?}"),
    })?;
    let owner = owner.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("windows stat missing OWNER line in {text:?}"),
    })?;
    let group = group.unwrap_or_else(|| owner.clone());
    let sddl = sddl.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("windows stat missing SDDL line in {text:?}"),
    })?;
    let mode_octal = synthetic_mode_from_sddl(&sddl);
    Ok(RemoteStat {
        size,
        mode_octal,
        owner_uid_or_sid: owner,
        group_gid_or_sid: group,
    })
}

/// Compute the synthetic Unix mode from an SDDL DACL. The mapping is
/// narrow on purpose: only the four cross-platform-allowed modes are
/// recognised. Any other ACL shape falls back to 0o600 so the
/// substage's mode assertions fail loudly rather than silently
/// accepting an unexpected ACL.
pub(crate) fn synthetic_mode_from_sddl(sddl: &str) -> u16 {
    // Inspect ACE strings for the well-known SIDs we install via the
    // mode → ACL mapping. WD = Everyone; BU = BUILTIN\Users. The
    // presence of either implies a world-readable mode.
    let world_readable = sddl.contains("(A;") && (sddl.contains(";WD)") || sddl.contains(";BU)"));
    if world_readable { 0o644 } else { 0o600 }
}

pub(crate) fn parse_run_argv_envelope(stdout: &str) -> Result<RemoteExitStatus, RemoteShellError> {
    let mut code: Option<i32> = None;
    let mut stdout_b64: Option<String> = None;
    let mut stderr_b64: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("CODE:") {
            code = Some(
                rest.trim()
                    .parse()
                    .map_err(|err| RemoteShellError::Protocol {
                        message: format!("run_argv CODE {rest:?} parse failed: {err}"),
                    })?,
            );
        } else if let Some(rest) = line.strip_prefix("STDOUT:") {
            stdout_b64 = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("STDERR:") {
            stderr_b64 = Some(rest.trim().to_owned());
        }
    }
    let code = code.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("run_argv envelope missing CODE in {stdout:?}"),
    })?;
    let stdout_b64 = stdout_b64.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("run_argv envelope missing STDOUT in {stdout:?}"),
    })?;
    let stderr_b64 = stderr_b64.ok_or_else(|| RemoteShellError::Protocol {
        message: format!("run_argv envelope missing STDERR in {stdout:?}"),
    })?;
    let stdout_bytes =
        decode_base64_strict(&stdout_b64).map_err(|err| RemoteShellError::Protocol {
            message: format!("run_argv stdout base64 decode failed: {err}"),
        })?;
    let stderr_bytes =
        decode_base64_strict(&stderr_b64).map_err(|err| RemoteShellError::Protocol {
            message: format!("run_argv stderr base64 decode failed: {err}"),
        })?;
    Ok(RemoteExitStatus {
        code,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

pub(crate) fn parse_windows_run_argv(stdout: &str) -> Result<RemoteExitStatus, RemoteShellError> {
    // The Windows envelope shares the CODE/STDOUT/STDERR sentinels
    // with the POSIX one, so the same parser handles both. Keeping
    // a thin alias here documents the contract instead of relying on
    // the reader to spot the shared parser.
    parse_run_argv_envelope(stdout)
}

// ── Encoding helpers ─────────────────────────────────────────────────────────

fn encode_base64_standard(bytes: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(bytes)
}

fn decode_base64_strict(input: &str) -> Result<Vec<u8>, RemoteShellError> {
    use base64::prelude::*;
    BASE64_STANDARD
        .decode(input.as_bytes())
        .map_err(|err| RemoteShellError::Protocol {
            message: format!("base64 decode failed: {err}"),
        })
}

fn utf16le_bytes(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for unit in input.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// PowerShell single-quoted string escape: every `'` doubles to
/// `''`. The caller is responsible for wrapping the result in single
/// quotes. Single-quoted PowerShell strings are literal — no `$var`
/// expansion, no backtick escapes, no subshell — so this is the
/// safest way to embed an arbitrary value in a PowerShell script.
pub(crate) fn powershell_single_quote_escape(value: &str) -> String {
    value.replace('\'', "''")
}

// ── In-process mock backend ──────────────────────────────────────────────────

/// In-process mock backend used by `remote_shell_tests`. Lives here
/// so the trait's contract tests can drive a deterministic in-memory
/// implementation without touching the live SSH path.
#[derive(Debug, Default)]
pub struct MockShellHost {
    inner: Mutex<MockShellState>,
}

#[derive(Debug, Default)]
struct MockShellState {
    files: BTreeMap<String, MockFile>,
    /// Programmed responses keyed by argv-joined-with-NUL, FIFO.
    run_responses: BTreeMap<String, Vec<RemoteExitStatus>>,
    /// Fallback response for any argv without an exact programmed
    /// match. Off by default so unprogrammed calls still error; set
    /// via `program_default_run_response` when a test needs to drive a
    /// helper past intermediate commands whose argv (e.g. a scratch
    /// dir with an embedded timestamp) cannot be predicted in advance.
    default_run_response: Option<RemoteExitStatus>,
    /// Recording of every run_argv call, for assertion in tests.
    run_log: Vec<MockRunInvocation>,
    /// Programmed TCP responses keyed by address, FIFO.
    tcp_responses: BTreeMap<String, Vec<Vec<u8>>>,
    /// Recording of every tcp_send_recv call.
    tcp_log: Vec<MockTcpInvocation>,
    /// Optional override for stat — when present takes priority over
    /// the synthetic stat computed from `files`.
    stat_override: BTreeMap<String, RemoteStat>,
}

#[derive(Debug, Clone)]
struct MockFile {
    bytes: Vec<u8>,
    mode_octal: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRunInvocation {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockTcpInvocation {
    pub addr: String,
    pub payload: Vec<u8>,
    pub timeout: Duration,
}

impl MockShellHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn program_run_response(&self, argv: &[&str], response: RemoteExitStatus) {
        let key = mock_argv_key(argv);
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.run_responses.entry(key).or_default().push(response);
    }

    pub fn program_default_run_response(&self, response: RemoteExitStatus) {
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.default_run_response = Some(response);
    }

    pub fn program_tcp_response(&self, addr: &str, response: Vec<u8>) {
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state
            .tcp_responses
            .entry(addr.to_owned())
            .or_default()
            .push(response);
    }

    pub fn set_stat_override(&self, remote_path: &str, stat: RemoteStat) {
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.stat_override.insert(remote_path.to_owned(), stat);
    }

    pub fn run_log(&self) -> Vec<MockRunInvocation> {
        self.inner
            .lock()
            .expect("mock shell mutex poisoned")
            .run_log
            .clone()
    }

    pub fn tcp_log(&self) -> Vec<MockTcpInvocation> {
        self.inner
            .lock()
            .expect("mock shell mutex poisoned")
            .tcp_log
            .clone()
    }
}

fn mock_argv_key(argv: &[&str]) -> String {
    argv.join("\0")
}

impl RemoteShellHost for MockShellHost {
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
        validate_remote_path(remote_path)?;
        let state = self.inner.lock().expect("mock shell mutex poisoned");
        state
            .files
            .get(remote_path)
            .map(|file| file.bytes.clone())
            .ok_or_else(|| RemoteShellError::Transport {
                message: format!("mock backend has no file at {remote_path}"),
            })
    }

    fn write_file(
        &self,
        remote_path: &str,
        bytes: &[u8],
        mode_octal: u16,
    ) -> Result<(), RemoteShellError> {
        validate_remote_path(remote_path)?;
        validate_mode_octal(mode_octal)?;
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.files.insert(
            remote_path.to_owned(),
            MockFile {
                bytes: bytes.to_vec(),
                mode_octal,
            },
        );
        Ok(())
    }

    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
        validate_remote_path(remote_path)?;
        let state = self.inner.lock().expect("mock shell mutex poisoned");
        if let Some(stat) = state.stat_override.get(remote_path) {
            return Ok(stat.clone());
        }
        let file = state
            .files
            .get(remote_path)
            .ok_or_else(|| RemoteShellError::Transport {
                message: format!("mock backend has no file at {remote_path}"),
            })?;
        Ok(RemoteStat {
            size: file.bytes.len() as u64,
            mode_octal: file.mode_octal,
            owner_uid_or_sid: "0".to_owned(),
            group_gid_or_sid: "0".to_owned(),
        })
    }

    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError> {
        validate_argv(argv)?;
        validate_env(env)?;
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.run_log.push(MockRunInvocation {
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            stdin: stdin.to_vec(),
        });
        let key = mock_argv_key(argv);
        let entry = state.run_responses.get_mut(&key);
        match entry {
            Some(queue) if !queue.is_empty() => Ok(queue.remove(0)),
            _ => match state.default_run_response.clone() {
                Some(response) => Ok(response),
                None => Err(RemoteShellError::Transport {
                    message: format!("mock backend has no programmed response for argv {argv:?}"),
                }),
            },
        }
    }

    fn tcp_send_recv(
        &self,
        addr: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteShellError> {
        let (_host, _port) = validate_tcp_addr(addr)?;
        let mut state = self.inner.lock().expect("mock shell mutex poisoned");
        state.tcp_log.push(MockTcpInvocation {
            addr: addr.to_owned(),
            payload: payload.to_vec(),
            timeout,
        });
        let entry = state.tcp_responses.get_mut(addr);
        match entry {
            Some(queue) if !queue.is_empty() => Ok(queue.remove(0)),
            _ => Err(RemoteShellError::Network {
                message: format!("mock backend has no programmed tcp response for {addr}"),
            }),
        }
    }
}

#[cfg(test)]
#[path = "remote_shell_tests.rs"]
mod tests;
