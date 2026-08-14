#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
// `Path` is only referenced from the unix helper server / exec path and the
// unix PF helpers; Windows uses only `PathBuf` (socket-path config fields).
#[cfg(not(windows))]
use std::path::Path;
use std::time::Duration;
// The helper *server*, its wire protocol, and subprocess exec are unix-only:
// on Windows the client/server both fail closed via `windows_ipc_blocker_reason`
// before touching any of this. Gate the supporting imports to match so Windows
// does not see them as unused.
#[cfg(not(windows))]
use std::fs;
#[cfg(not(windows))]
use std::io::{Read, Write};
#[cfg(not(windows))]
use std::net::Shutdown;
#[cfg(not(windows))]
use std::process::{Command, ExitStatus, Stdio};
#[cfg(not(windows))]
use std::thread::sleep;
#[cfg(not(windows))]
use std::time::Instant;

#[cfg(not(windows))]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(not(windows))]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use crate::windows_ipc::{
    DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH, WindowsLocalIpcRole, validate_windows_pipe_path,
    windows_ipc_blocker_reason,
};
#[cfg(not(windows))]
use nix::sys::socket::getsockopt;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
use nix::sys::socket::sockopt::LocalPeerCred;
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::sockopt::PeerCredentials;
#[cfg(not(windows))]
use nix::unistd::{Gid, Group, Uid, chown};
// Socket-security validators are used only by the `#[cfg(not(windows))]`
// `validate_privileged_helper_socket_security`; Windows validates its named-pipe
// path separately and never binds a unix socket.
#[cfg(not(windows))]
use rustynet_local_security::{
    validate_owner_only_socket, validate_root_managed_shared_runtime_socket,
};

#[cfg(not(windows))]
pub const DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH: &str = "/run/rustynet/rustynetd-privileged.sock";
#[cfg(windows)]
pub const DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH: &str = DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH;
pub const DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS: u64 = 2_000;

// The frame/size constants below describe the unix helper wire protocol, which
// Windows never speaks (the IPC path fails closed first). Gate them to match.
#[cfg(not(windows))]
const HELPER_FRAME_MAGIC: [u8; 4] = *b"RNHF";
#[cfg(not(windows))]
const HELPER_FRAME_VERSION: u8 = 1;
#[cfg(not(windows))]
const HELPER_FRAME_TYPE_REQUEST: u8 = 1;
#[cfg(not(windows))]
const HELPER_FRAME_TYPE_RESPONSE: u8 = 2;
#[cfg(not(windows))]
const HELPER_FRAME_HEADER_BYTES: usize = 10;
#[cfg(not(windows))]
const MAX_MESSAGE_BYTES: usize = 16_384;
#[cfg(not(windows))]
const MAX_OUTPUT_BYTES: usize = 65_536;
pub(crate) const MAX_ARGS: usize = 128;
pub(crate) const MAX_ARG_BYTES: usize = 256;
#[cfg(not(windows))]
const MAX_PROGRAM_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedCommandProgram {
    Ip,
    Nft,
    Wg,
    Sysctl,
    Ifconfig,
    Route,
    Pfctl,
    WireguardGo,
    Kill,
    /// In-helper file-write builtin for protected-mode DNS fail-closed
    /// (`linux_dns_protect`). NOT an external binary: the single argument is a
    /// fixed selector and the helper owns the path→content mapping, so no path
    /// or file content ever crosses the privileged boundary.
    DnsFailclosedFile,
    /// In-helper macOS `pf` anchor load builtin (`macos_pf_load_spec`). NOT an
    /// external binary: the arguments are a validated STRUCTURED spec; the
    /// helper re-renders the `pf` rule text from the reviewed builders, derives
    /// the anchor name itself, and owns the temp file + `pfctl` invocation. No
    /// rule text, file path, or anchor name supplied by the daemon is ever
    /// loaded — this closes the `pfctl -f` boundary (audit major #5).
    MacosPfLoad,
    /// In-helper firewalld zone builtin (`linux_firewalld_zone`). NOT an
    /// external binary. Binds the tunnel interface to firewalld's EFFECTIVE
    /// DEFAULT ZONE at runtime, over the D-Bus zone API, so that firewalld's own
    /// forward chain (which runs AFTER ours and ends in a reject) stops
    /// destroying traffic this daemon already authorised. The zone name is not
    /// expressible by the caller: the helper always sends the empty string and
    /// firewalld resolves the default server-side, so `trusted` and every other
    /// zone are unrepresentable rather than merely validated against (QH-46).
    LinuxFirewalldZone,
}

impl PrivilegedCommandProgram {
    pub fn as_str(self) -> &'static str {
        match self {
            PrivilegedCommandProgram::Ip => "ip",
            PrivilegedCommandProgram::Nft => "nft",
            PrivilegedCommandProgram::Wg => "wg",
            PrivilegedCommandProgram::Sysctl => "sysctl",
            PrivilegedCommandProgram::Ifconfig => "ifconfig",
            PrivilegedCommandProgram::Route => "route",
            PrivilegedCommandProgram::Pfctl => "pfctl",
            PrivilegedCommandProgram::WireguardGo => "wireguard-go",
            PrivilegedCommandProgram::Kill => "kill",
            PrivilegedCommandProgram::DnsFailclosedFile => {
                crate::linux_dns_protect::DNS_FAILCLOSED_FILE_PROGRAM
            }
            PrivilegedCommandProgram::MacosPfLoad => {
                crate::macos_pf_load_spec::MACOS_PF_LOAD_PROGRAM
            }
            PrivilegedCommandProgram::LinuxFirewalldZone => {
                crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
            }
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(PrivilegedCommandProgram::Ip),
            "nft" => Some(PrivilegedCommandProgram::Nft),
            "wg" => Some(PrivilegedCommandProgram::Wg),
            "sysctl" => Some(PrivilegedCommandProgram::Sysctl),
            "ifconfig" => Some(PrivilegedCommandProgram::Ifconfig),
            "route" => Some(PrivilegedCommandProgram::Route),
            "pfctl" => Some(PrivilegedCommandProgram::Pfctl),
            "wireguard-go" => Some(PrivilegedCommandProgram::WireguardGo),
            "kill" => Some(PrivilegedCommandProgram::Kill),
            _ if value == crate::linux_dns_protect::DNS_FAILCLOSED_FILE_PROGRAM => {
                Some(PrivilegedCommandProgram::DnsFailclosedFile)
            }
            _ if value == crate::macos_pf_load_spec::MACOS_PF_LOAD_PROGRAM => {
                Some(PrivilegedCommandProgram::MacosPfLoad)
            }
            _ if value == crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM => {
                Some(PrivilegedCommandProgram::LinuxFirewalldZone)
            }
            _ => None,
        }
    }

    /// True for in-helper builtins that have no external binary to exec. The
    /// exec path (`resolve_binary` / `run_privileged_subprocess`) must never run
    /// for these — the dispatcher routes them to their in-process handler.
    fn is_builtin(self) -> bool {
        matches!(
            self,
            PrivilegedCommandProgram::DnsFailclosedFile
                | PrivilegedCommandProgram::MacosPfLoad
                | PrivilegedCommandProgram::LinuxFirewalldZone
        )
    }

    // Binary resolution + the privileged exec path only run inside the unix
    // helper server; Windows fails closed before any command is dispatched.
    #[cfg(not(windows))]
    fn binary_candidates(self) -> &'static [&'static str] {
        match self {
            PrivilegedCommandProgram::Ip => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
            PrivilegedCommandProgram::Nft => &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"],
            PrivilegedCommandProgram::Wg => &["/usr/bin/wg", "/usr/sbin/wg", "/sbin/wg"],
            PrivilegedCommandProgram::Sysctl => {
                &["/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"]
            }
            PrivilegedCommandProgram::Ifconfig => {
                &["/sbin/ifconfig", "/usr/sbin/ifconfig", "/usr/bin/ifconfig"]
            }
            PrivilegedCommandProgram::Route => {
                &["/sbin/route", "/usr/sbin/route", "/usr/bin/route"]
            }
            PrivilegedCommandProgram::Pfctl => &["/sbin/pfctl", "/usr/sbin/pfctl"],
            PrivilegedCommandProgram::WireguardGo => &[
                "/usr/local/bin/wireguard-go",
                "/opt/homebrew/bin/wireguard-go",
                "/usr/bin/wireguard-go",
            ],
            PrivilegedCommandProgram::Kill => &["/bin/kill", "/usr/bin/kill"],
            // In-helper builtins: no external binary for the program itself.
            // Routed to their in-process handler before exec; the empty
            // candidate set fails closed if it ever reaches binary resolution.
            // (The macOS pf-load builtin internally resolves `pfctl` via the
            // Pfctl candidate set, not this one.)
            PrivilegedCommandProgram::DnsFailclosedFile
            | PrivilegedCommandProgram::MacosPfLoad
            | PrivilegedCommandProgram::LinuxFirewalldZone => &[],
        }
    }

    #[cfg(not(windows))]
    fn resolve_binary(self) -> Result<PathBuf, String> {
        if self.is_builtin() {
            return Err(format!(
                "{self} is an in-helper builtin and has no external binary to execute"
            ));
        }
        for candidate in self.binary_candidates() {
            let candidate_path = Path::new(candidate);
            if !candidate_path.exists() {
                continue;
            }
            return validate_privileged_program_binary(candidate_path, self.as_str());
        }
        Err(format!("no supported binary path found for {self}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedCommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl PrivilegedCommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedCommandClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl PrivilegedCommandClient {
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Result<Self, String> {
        if socket_path.as_os_str().is_empty() {
            return Err("privileged helper socket path must not be empty".to_owned());
        }
        #[cfg(windows)]
        {
            validate_windows_pipe_path(&socket_path, WindowsLocalIpcRole::PrivilegedHelper)?;
        }
        #[cfg(not(windows))]
        if !socket_path.is_absolute() {
            return Err("privileged helper socket path must be absolute".to_owned());
        }
        Ok(Self {
            socket_path,
            timeout,
        })
    }

    pub fn run_capture(
        &self,
        program: PrivilegedCommandProgram,
        args: &[&str],
    ) -> Result<PrivilegedCommandOutput, String> {
        validate_request(program, args)?;
        #[cfg(windows)]
        {
            validate_windows_pipe_path(&self.socket_path, WindowsLocalIpcRole::PrivilegedHelper)?;
            let _ = program;
            let _ = args;
            let _ = self.timeout;
            Err(windows_ipc_blocker_reason(
                WindowsLocalIpcRole::PrivilegedHelper,
            ))
        }
        #[cfg(not(windows))]
        {
            validate_privileged_helper_socket_security(&self.socket_path)?;
            let mut stream = UnixStream::connect(&self.socket_path).map_err(|err| {
                format!(
                    "privileged helper connect failed ({}): {err}",
                    self.socket_path.display()
                )
            })?;
            stream
                .set_read_timeout(Some(self.timeout))
                .map_err(|err| format!("privileged helper read-timeout failed: {err}"))?;
            stream
                .set_write_timeout(Some(self.timeout))
                .map_err(|err| format!("privileged helper write-timeout failed: {err}"))?;

            // RN-17: re-verify the connected peer on the established fd, not
            // just the pre-connect path metadata. This closes the
            // connect-after-validate TOCTOU: if the socket inode was swapped
            // between the security check and connect(), we would be talking to
            // an impostor. The helper runs as root (uid 0) in production; we
            // also accept a peer with the client's own uid (a non-privilege-
            // separated / same-user deployment, and the in-process test
            // harness). A peer owned by any *other* uid — the cross-uid swap
            // that is the actual threat — is rejected (fail closed).
            let own_uid = nix::unistd::getuid().as_raw();
            match peer_uid(&stream) {
                Some(uid) if uid == 0 || uid == own_uid => {}
                other => {
                    return Err(format!(
                        "privileged helper peer uid {other:?} is neither root nor the \
                         client uid ({own_uid}); refusing to send privileged command"
                    ));
                }
            }

            let request = HelperRequest {
                program: program.as_str().to_owned(),
                args: args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>(),
            };
            write_request_frame(&mut stream, &request)?;
            let response = read_response_frame(&mut stream)?;
            if !response.ok {
                return Err(response.error.unwrap_or_else(|| {
                    "privileged helper reported an unknown failure".to_owned()
                }));
            }
            Ok(PrivilegedCommandOutput {
                status: response.status.unwrap_or(-1),
                stdout: response.stdout.unwrap_or_default(),
                stderr: response.stderr.unwrap_or_default(),
            })
        }
    }
}

#[cfg(not(windows))]
fn rustynetd_service_gid_for_socket(path: &Path) -> Option<u32> {
    let shared_runtime = path.starts_with("/run/rustynet")
        || path.starts_with("/var/run/rustynet")
        || path.starts_with("/private/var/run/rustynet");
    if !shared_runtime {
        return None;
    }
    Group::from_name("rustynetd")
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

#[cfg(not(windows))]
fn validate_privileged_helper_socket_security(path: &Path) -> Result<(), String> {
    let expected_uid = Uid::effective().as_raw();
    let allowed_owner_uids = [expected_uid, 0];
    if let Some(service_gid) = rustynetd_service_gid_for_socket(path) {
        return validate_root_managed_shared_runtime_socket(
            path,
            "privileged helper socket",
            &allowed_owner_uids,
            &allowed_owner_uids,
            service_gid,
        );
    }
    validate_owner_only_socket(
        path,
        "privileged helper socket",
        &allowed_owner_uids,
        &allowed_owner_uids,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedHelperConfig {
    pub socket_path: PathBuf,
    pub allowed_uid: u32,
    pub allowed_gid: Option<u32>,
    pub io_timeout: Duration,
}

impl Default for PrivilegedHelperConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH),
            allowed_uid: 0,
            allowed_gid: None,
            io_timeout: Duration::from_millis(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS),
        }
    }
}

pub fn run_privileged_helper(config: PrivilegedHelperConfig) -> Result<(), String> {
    if config.socket_path.as_os_str().is_empty() {
        return Err("privileged helper socket path must not be empty".to_owned());
    }
    #[cfg(windows)]
    {
        validate_windows_pipe_path(&config.socket_path, WindowsLocalIpcRole::PrivilegedHelper)?;
        let _ = config.allowed_uid;
        let _ = config.allowed_gid;
        let _ = config.io_timeout;
        Err(windows_ipc_blocker_reason(
            WindowsLocalIpcRole::PrivilegedHelper,
        ))
    }
    #[cfg(not(windows))]
    if !config.socket_path.is_absolute() {
        return Err("privileged helper socket path must be absolute".to_owned());
    }

    #[cfg(not(windows))]
    {
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "create privileged helper socket parent {} failed: {err}",
                    parent.display()
                )
            })?;
            if let Some(gid) = config.allowed_gid {
                chown(parent, None, Some(Gid::from_raw(gid))).map_err(|err| {
                    format!(
                        "set privileged helper socket parent group {} failed: {err}",
                        parent.display()
                    )
                })?;
            }
            let parent_mode = if config.allowed_gid.is_some() {
                0o770
            } else {
                0o700
            };
            fs::set_permissions(parent, fs::Permissions::from_mode(parent_mode)).map_err(
                |err| {
                    format!(
                        "set privileged helper socket parent permissions {} failed: {err}",
                        parent.display()
                    )
                },
            )?;
        }

        if config.socket_path.exists() {
            let metadata = fs::symlink_metadata(&config.socket_path).map_err(|err| {
                format!(
                    "inspect existing privileged helper socket {} failed: {err}",
                    config.socket_path.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err("privileged helper socket path must not be a symlink".to_owned());
            }
            if !metadata.file_type().is_socket() {
                return Err(format!(
                    "privileged helper socket path exists but is not a socket: {}",
                    config.socket_path.display()
                ));
            }
            fs::remove_file(&config.socket_path).map_err(|err| {
                format!(
                    "remove existing privileged helper socket {} failed: {err}",
                    config.socket_path.display()
                )
            })?;
        }

        let listener = UnixListener::bind(&config.socket_path).map_err(|err| {
            format!(
                "bind privileged helper socket {} failed: {err}",
                config.socket_path.display()
            )
        })?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660)).map_err(
            |err| {
                format!(
                    "set privileged helper socket permissions {} failed: {err}",
                    config.socket_path.display()
                )
            },
        )?;
        if let Some(gid) = config.allowed_gid {
            chown(&config.socket_path, None, Some(Gid::from_raw(gid))).map_err(|err| {
                format!(
                    "set privileged helper socket group {} failed: {err}",
                    config.socket_path.display()
                )
            })?;
        }

        loop {
            let (mut stream, _) = listener
                .accept()
                .map_err(|err| format!("accept privileged helper connection failed: {err}"))?;
            stream
                .set_read_timeout(Some(config.io_timeout))
                .map_err(|err| format!("set privileged helper read-timeout failed: {err}"))?;
            stream
                .set_write_timeout(Some(config.io_timeout))
                .map_err(|err| format!("set privileged helper write-timeout failed: {err}"))?;

            let authorized =
                peer_uid(&stream).is_some_and(|uid| uid == config.allowed_uid || uid == 0);
            if !authorized {
                let _ = write_response(
                    &mut stream,
                    HelperResponse::error("unauthorized privileged helper peer".to_owned()),
                );
                continue;
            }

            // On macOS, peek first 4 bytes to dispatch RNUF (utun open) vs
            // RNHF (command). On other Unixes there is no utun helper so
            // the peek + dispatch is unconditional RNHF and we skip the peek.
            // The peek uses libc::recv with MSG_PEEK (in
            // macos_utun_helper_unsafe) because UnixStream::peek is still
            // nightly-only (unix_socket_peek).
            #[cfg(target_os = "macos")]
            {
                let peek_buf = crate::macos_utun_helper_unsafe::peek_first_4_bytes(&stream)
                    .unwrap_or([0u8; 4]);
                if peek_buf == crate::macos_utun_helper::RNUF_MAGIC {
                    let _ = crate::macos_utun_helper_server::handle_utun_open_request(stream);
                    continue;
                }
            }

            let response = match read_request(&mut stream) {
                Ok(request) => handle_request_with_timeout(request, config.io_timeout),
                Err(err) => HelperResponse::error(err),
            };
            let _ = write_response(&mut stream, response);
        }
    }
}

// The request/response value types are the in-memory form of the unix helper
// wire protocol; Windows never constructs them (its IPC path fails closed).
// pub(crate): the phase10.rs test-only mock helper server reuses these plus
// read_request/write_response below (rather than hand-rolling its own copy of
// the wire format) so the mock can never drift from the real codec again —
// see the iproute2-6.19-fib-table-fix triage that found the mock speaking a
// stale pre-framing JSON-line protocol.
#[cfg(not(windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperRequest {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

#[cfg(not(windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperResponse {
    ok: bool,
    status: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

#[cfg(not(windows))]
impl HelperResponse {
    pub(crate) fn error(message: String) -> Self {
        Self {
            ok: false,
            status: None,
            stdout: None,
            stderr: None,
            error: Some(message),
        }
    }

    pub(crate) fn success(status: i32, stdout: String, stderr: String) -> Self {
        Self {
            ok: true,
            status: Some(status),
            stdout: Some(stdout),
            stderr: Some(stderr),
            error: None,
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn read_request(stream: &mut UnixStream) -> Result<HelperRequest, String> {
    let request_bytes = read_frame(stream, HELPER_FRAME_TYPE_REQUEST)?;
    decode_helper_request(&request_bytes).map_err(|err| format!("request decode failed: {err}"))
}

#[cfg(not(windows))]
pub(crate) fn write_response(
    stream: &mut UnixStream,
    response: HelperResponse,
) -> Result<(), String> {
    let response_bytes = encode_helper_response(&response)
        .map_err(|err| format!("encode response failed: {err}"))?;
    write_frame(stream, HELPER_FRAME_TYPE_RESPONSE, &response_bytes)
}

#[cfg(not(windows))]
fn write_request_frame(stream: &mut UnixStream, request: &HelperRequest) -> Result<(), String> {
    let request_bytes = encode_helper_request(request)
        .map_err(|err| format!("privileged helper request encode failed: {err}"))?;
    write_frame(stream, HELPER_FRAME_TYPE_REQUEST, &request_bytes)
        .map_err(|err| format!("privileged helper request write failed: {err}"))
}

#[cfg(not(windows))]
fn read_response_frame(stream: &mut UnixStream) -> Result<HelperResponse, String> {
    let response_bytes = read_frame(stream, HELPER_FRAME_TYPE_RESPONSE)
        .map_err(|err| format!("privileged helper response read failed: {err}"))
        .map_err(annotate_helper_response_read_error)?;
    decode_helper_response(&response_bytes)
        .map_err(|err| format!("privileged helper response decode failed: {err}"))
}

/// Add the operational cause to a truncated-response error.
///
/// On a length-prefixed IPC, an `UnexpectedEof` mid-frame means the peer went
/// away — it is never data corruption. The overwhelmingly common reason is the
/// helper's own I/O timeout elapsing while it runs a privileged command, after
/// which it drops the connection and the daemon reports a *framing* fault. That
/// wording sends the reader looking for protocol damage instead of at a
/// too-tight timeout: observed live on a 2-core guest as a continuous
/// `truncated frame header` loop that stopped dead when the timeout was raised
/// from 2000 ms to 10000 ms. Name the knob so the next reader does not have to
/// rediscover it.
#[cfg(not(windows))]
fn annotate_helper_response_read_error(message: String) -> String {
    if !message.contains("truncated") {
        return message;
    }
    format!(
        "{message} (the helper closed the connection mid-frame -- this is not protocol \
         corruption; it is usually the helper's own I/O timeout elapsing while it runs a \
         privileged command, so raise --timeout-ms / \
         RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS before suspecting the transport)"
    )
}

#[cfg(not(windows))]
fn write_frame(stream: &mut UnixStream, message_type: u8, payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("frame payload must not be empty".to_owned());
    }
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err("frame payload exceeds maximum size".to_owned());
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| "frame payload length overflow".to_owned())?;
    let mut header = [0u8; HELPER_FRAME_HEADER_BYTES];
    header[..4].copy_from_slice(&HELPER_FRAME_MAGIC);
    header[4] = HELPER_FRAME_VERSION;
    header[5] = message_type;
    header[6..10].copy_from_slice(&payload_len.to_be_bytes());
    stream
        .write_all(&header)
        .map_err(|err| format!("write frame header failed: {err}"))?;
    stream
        .write_all(payload)
        .map_err(|err| format!("write frame payload failed: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("flush frame failed: {err}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|err| format!("shutdown frame writer failed: {err}"))
}

#[cfg(not(windows))]
fn read_frame(stream: &mut UnixStream, expected_message_type: u8) -> Result<Vec<u8>, String> {
    let mut header = [0u8; HELPER_FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut header)
        .map_err(|err| map_read_exact_error(err, "frame header"))?;
    if header[..4] != HELPER_FRAME_MAGIC {
        return Err("invalid frame magic".to_owned());
    }
    if header[4] != HELPER_FRAME_VERSION {
        return Err(format!(
            "unsupported frame version {}; expected {}",
            header[4], HELPER_FRAME_VERSION
        ));
    }
    if header[5] != expected_message_type {
        return Err(format!(
            "unexpected frame type {}; expected {}",
            header[5], expected_message_type
        ));
    }
    let payload_len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if payload_len == 0 {
        return Err("frame payload must not be empty".to_owned());
    }
    if payload_len > MAX_MESSAGE_BYTES {
        return Err("frame payload exceeds maximum size".to_owned());
    }
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| map_read_exact_error(err, "frame payload"))?;
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(payload),
        Ok(_) => Err("trailing bytes after frame payload".to_owned()),
        Err(err) => Err(format!("read frame trailer failed: {err}")),
    }
}

// The helper wire-protocol codec (request/response encode + decode and its
// primitive field helpers) is unix-only — Windows never frames a helper message.
#[cfg(not(windows))]
fn map_read_exact_error(err: std::io::Error, label: &str) -> String {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return format!("truncated {label}");
    }
    format!("read {label} failed: {err}")
}

#[cfg(not(windows))]
fn encode_helper_request(request: &HelperRequest) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    encode_string_field(
        &mut payload,
        request.program.as_str(),
        "program",
        MAX_PROGRAM_BYTES,
    )?;
    let arg_count = u16::try_from(request.args.len())
        .map_err(|_| "argument count exceeds protocol limit".to_owned())?;
    payload.extend_from_slice(&arg_count.to_be_bytes());
    for arg in &request.args {
        encode_string_field(&mut payload, arg.as_str(), "arg", MAX_ARG_BYTES)?;
    }
    Ok(payload)
}

#[cfg(not(windows))]
fn decode_helper_request(payload: &[u8]) -> Result<HelperRequest, String> {
    let mut cursor = 0usize;
    let program = decode_string_field(payload, &mut cursor, "program", MAX_PROGRAM_BYTES)?;
    let arg_count = decode_u16(payload, &mut cursor, "arg_count")? as usize;
    if arg_count > MAX_ARGS {
        return Err(format!("argument count exceeds maximum ({MAX_ARGS})"));
    }
    let mut args = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        args.push(decode_string_field(
            payload,
            &mut cursor,
            "arg",
            MAX_ARG_BYTES,
        )?);
    }
    ensure_payload_consumed(payload, cursor)?;
    Ok(HelperRequest { program, args })
}

#[cfg(not(windows))]
fn encode_helper_response(response: &HelperResponse) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    payload.push(u8::from(response.ok));
    encode_optional_i32(&mut payload, response.status);
    encode_optional_string_field(&mut payload, response.stdout.as_deref(), "stdout")?;
    encode_optional_string_field(&mut payload, response.stderr.as_deref(), "stderr")?;
    encode_optional_string_field(&mut payload, response.error.as_deref(), "error")?;
    Ok(payload)
}

#[cfg(not(windows))]
fn decode_helper_response(payload: &[u8]) -> Result<HelperResponse, String> {
    let mut cursor = 0usize;
    let ok = decode_bool(payload, &mut cursor, "ok")?;
    let status = decode_optional_i32(payload, &mut cursor, "status")?;
    let stdout = decode_optional_string_field(payload, &mut cursor, "stdout", MAX_OUTPUT_BYTES)?;
    let stderr = decode_optional_string_field(payload, &mut cursor, "stderr", MAX_OUTPUT_BYTES)?;
    let error = decode_optional_string_field(payload, &mut cursor, "error", MAX_OUTPUT_BYTES)?;
    ensure_payload_consumed(payload, cursor)?;
    Ok(HelperResponse {
        ok,
        status,
        stdout,
        stderr,
        error,
    })
}

#[cfg(not(windows))]
fn encode_optional_i32(payload: &mut Vec<u8>, value: Option<i32>) {
    match value {
        Some(value) => {
            payload.push(1);
            payload.extend_from_slice(&value.to_be_bytes());
        }
        None => payload.push(0),
    }
}

#[cfg(not(windows))]
fn decode_optional_i32(
    payload: &[u8],
    cursor: &mut usize,
    label: &str,
) -> Result<Option<i32>, String> {
    match decode_bool_flag(payload, cursor, label)? {
        false => Ok(None),
        true => Ok(Some(decode_i32(payload, cursor, label)?)),
    }
}

#[cfg(not(windows))]
fn encode_optional_string_field(
    payload: &mut Vec<u8>,
    value: Option<&str>,
    label: &str,
) -> Result<(), String> {
    match value {
        Some(value) => {
            payload.push(1);
            encode_string_field(payload, value, label, MAX_MESSAGE_BYTES)?;
        }
        None => payload.push(0),
    }
    Ok(())
}

#[cfg(not(windows))]
fn decode_optional_string_field(
    payload: &[u8],
    cursor: &mut usize,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    match decode_bool_flag(payload, cursor, label)? {
        false => Ok(None),
        true => Ok(Some(decode_string_field(
            payload, cursor, label, max_bytes,
        )?)),
    }
}

#[cfg(not(windows))]
fn encode_string_field(
    payload: &mut Vec<u8>,
    value: &str,
    label: &str,
    max_bytes: usize,
) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds maximum size ({max_bytes} bytes)"));
    }
    let value_len =
        u16::try_from(bytes.len()).map_err(|_| format!("{label} length exceeds protocol limit"))?;
    payload.extend_from_slice(&value_len.to_be_bytes());
    payload.extend_from_slice(bytes);
    Ok(())
}

#[cfg(not(windows))]
fn decode_string_field(
    payload: &[u8],
    cursor: &mut usize,
    label: &str,
    max_bytes: usize,
) -> Result<String, String> {
    let len = decode_u16(payload, cursor, label)? as usize;
    if len > max_bytes {
        return Err(format!("{label} exceeds maximum size ({max_bytes} bytes)"));
    }
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| format!("{label} length overflow"))?;
    let value_bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| format!("truncated {label}"))?;
    *cursor = end;
    std::str::from_utf8(value_bytes)
        .map_err(|err| format!("{label} is not valid utf-8: {err}"))
        .map(str::to_string)
}

#[cfg(not(windows))]
fn decode_bool(payload: &[u8], cursor: &mut usize, label: &str) -> Result<bool, String> {
    match decode_u8(payload, cursor, label)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(format!("invalid {label} flag {value}")),
    }
}

#[cfg(not(windows))]
fn decode_bool_flag(payload: &[u8], cursor: &mut usize, label: &str) -> Result<bool, String> {
    decode_bool(payload, cursor, label)
}

#[cfg(not(windows))]
fn decode_u8(payload: &[u8], cursor: &mut usize, label: &str) -> Result<u8, String> {
    let byte = *payload
        .get(*cursor)
        .ok_or_else(|| format!("truncated {label}"))?;
    *cursor += 1;
    Ok(byte)
}

#[cfg(not(windows))]
fn decode_u16(payload: &[u8], cursor: &mut usize, label: &str) -> Result<u16, String> {
    let bytes = decode_fixed::<2>(payload, cursor, label)?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(not(windows))]
fn decode_i32(payload: &[u8], cursor: &mut usize, label: &str) -> Result<i32, String> {
    let bytes = decode_fixed::<4>(payload, cursor, label)?;
    Ok(i32::from_be_bytes(bytes))
}

#[cfg(not(windows))]
fn decode_fixed<const N: usize>(
    payload: &[u8],
    cursor: &mut usize,
    label: &str,
) -> Result<[u8; N], String> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| format!("{label} length overflow"))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| format!("truncated {label}"))?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| format!("invalid fixed-width payload for {label}"))
}

#[cfg(not(windows))]
fn ensure_payload_consumed(payload: &[u8], cursor: usize) -> Result<(), String> {
    if cursor != payload.len() {
        return Err("trailing bytes after helper payload".to_owned());
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
fn handle_request(request: HelperRequest) -> HelperResponse {
    handle_request_with_timeout(
        request,
        Duration::from_millis(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS),
    )
}

// Helper-side request dispatch + exec only run on unix; Windows fails closed.
#[cfg(not(windows))]
fn handle_request_with_timeout(request: HelperRequest, timeout: Duration) -> HelperResponse {
    let program = match PrivilegedCommandProgram::parse(&request.program) {
        Some(program) => program,
        None => {
            return HelperResponse::error(format!(
                "unsupported privileged command program: {}",
                request.program
            ));
        }
    };
    let args = request.args.iter().map(String::as_str).collect::<Vec<_>>();
    if let Err(err) = validate_request(program, &args) {
        return HelperResponse::error(err);
    }

    // In-helper builtins do not exec an external binary. They are dispatched to
    // their in-process handler after the same allowlist validation as every
    // exec'd command.
    if program.is_builtin() {
        return match execute_builtin(program, &args) {
            Ok(output) => HelperResponse::success(output.status, output.stdout, output.stderr),
            Err(err) => HelperResponse::error(err),
        };
    }

    let binary = match program.resolve_binary() {
        Ok(path) => path,
        Err(err) => return HelperResponse::error(err),
    };

    match run_privileged_subprocess(&binary, &request.args, timeout) {
        Ok(output) => {
            let status = exit_status_code(output.status);
            let stdout = truncate_lossy(&output.stdout, MAX_OUTPUT_BYTES);
            let stderr = truncate_lossy(&output.stderr, MAX_OUTPUT_BYTES);
            HelperResponse::success(status, stdout, stderr)
        }
        Err(err) => HelperResponse::error(format!(
            "{program} command execution failed ({}): {err}",
            binary.display(),
        )),
    }
}

/// Run an in-helper builtin (no external binary). The caller must have already
/// validated `args` via [`validate_request`]. Returns a captured-output value so
/// both the IPC helper and the helper-less direct path can surface the result
/// uniformly.
fn execute_builtin(
    program: PrivilegedCommandProgram,
    args: &[&str],
) -> Result<PrivilegedCommandOutput, String> {
    match program {
        PrivilegedCommandProgram::DnsFailclosedFile => {
            // `args` validated as exactly `[selector]`; the executor owns the
            // path→content mapping and re-validates the selector defensively.
            crate::linux_dns_protect::apply_dns_failclosed_file(args[0]).map(|()| {
                PrivilegedCommandOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }
            })
        }
        PrivilegedCommandProgram::MacosPfLoad => execute_macos_pf_load(args),
        #[cfg(not(windows))]
        PrivilegedCommandProgram::LinuxFirewalldZone => execute_linux_firewalld_zone(args),
        // No other builtins exist; fail closed if one is added without a handler.
        _ => Err(format!("no in-process handler for builtin {program}")),
    }
}

/// Run the macOS `pf` anchor load builtin. The `args` were already validated as
/// a decodable spec; we re-decode (defensive), re-render the rule text from the
/// reviewed builders, derive the anchor name from the spec kind, write the rules
/// to a ROOT-OWNED temp in a root-only directory, and load it with `pfctl`.
/// Nothing the daemon supplied — rule text, file path, or anchor — reaches
/// `pfctl`.
fn execute_macos_pf_load(args: &[&str]) -> Result<PrivilegedCommandOutput, String> {
    let spec = crate::macos_pf_load_spec::MacosPfLoadSpec::decode(args)?;
    let anchor = spec.anchor_name();
    let rules = spec.render()?;
    load_macos_pf_anchor(&anchor, &rules)?;
    Ok(PrivilegedCommandOutput {
        status: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

/// Run the `linux-firewalld-zone` builtin (QH-46).
///
/// # Why D-Bus and not `firewall-cmd`
///
/// `firewall-cmd --add-interface` routes through a path that writes
/// `connection.zone` into `/etc/NetworkManager/system-connections/*.nmconnection`
/// — a third daemon's on-disk configuration, which then outlives this daemon's
/// uninstall and role demotion. The D-Bus `addInterface` method has no such
/// branch. Going through the bus removes that persistence hazard by mechanism
/// rather than mitigating it afterwards, and keeps a python CLI out of a
/// privileged exec path.
///
/// # What crosses the boundary
///
/// Every token in every argv below is a helper-owned constant except the
/// interface name, which `validate_request` already constrained to a plausible
/// device name that is not the loopback, and which is re-checked here against
/// sysfs so that only a VIRTUAL device (a tunnel, not a physical NIC) can be
/// bound. The zone is always the empty string, which firewalld resolves to the
/// effective default zone server-side, so no zone name is expressible at all.
#[cfg(not(windows))]
fn execute_linux_firewalld_zone(args: &[&str]) -> Result<PrivilegedCommandOutput, String> {
    use crate::linux_firewalld_zone::{
        FirewalldPosture, FirewalldPresence, FirewalldZoneOp, FirewalldZoneSpec,
    };

    let spec = FirewalldZoneSpec::decode(args)?;
    let busctl = resolve_busctl_binary()?;

    // 1. Presence. This is backend-independent: it asks the bus who owns the
    //    name, so it is correct whether firewalld drives nftables or iptables.
    let owner = run_busctl(
        &busctl,
        &[
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.fedoraproject.FirewallD1",
        ],
    );
    let presence = match owner {
        Ok(out) if out.contains("true") => FirewalldPresence::Running,
        Ok(out) if out.contains("false") => FirewalldPresence::Absent,
        // A probe that could not be completed must NOT be reported as absence:
        // that is precisely the fail-open this builtin exists to prevent.
        _ => FirewalldPresence::Unknown,
    };

    if presence == FirewalldPresence::Absent {
        // Nothing to coexist with. Report and mutate nothing.
        let posture = FirewalldPosture {
            presence,
            default_zone: None,
            interface_bound: None,
        };
        return Ok(PrivilegedCommandOutput {
            status: 0,
            stdout: posture.encode(),
            stderr: String::new(),
        });
    }

    let default_zone = run_busctl(
        &busctl,
        &[
            "call",
            "org.fedoraproject.FirewallD1",
            "/org/fedoraproject/FirewallD1",
            "org.fedoraproject.FirewallD1",
            "getDefaultZone",
        ],
    )
    .ok()
    .and_then(|out| extract_busctl_string(out.as_str()));

    if spec.op == FirewalldZoneOp::Bind {
        // Only a virtual device may be bound. A physical NIC is already in a
        // zone by the operator's own configuration and is none of our business.
        require_virtual_network_device(spec.interface.as_str())?;
        // `addInterface` is idempotent from our side: ZONE_ALREADY_SET means the
        // desired end state already holds, which the verification below settles
        // authoritatively either way.
        let _ = run_busctl(
            &busctl,
            &[
                "call",
                "org.fedoraproject.FirewallD1",
                "/org/fedoraproject/FirewallD1",
                "org.fedoraproject.FirewallD1.zone",
                "addInterface",
                "ss",
                "",
                spec.interface.as_str(),
            ],
        );
    } else if spec.op == FirewalldZoneOp::Unbind {
        let _ = run_busctl(
            &busctl,
            &[
                "call",
                "org.fedoraproject.FirewallD1",
                "/org/fedoraproject/FirewallD1",
                "org.fedoraproject.FirewallD1.zone",
                "removeInterface",
                "ss",
                "",
                spec.interface.as_str(),
            ],
        );
    }

    // Re-read the binding rather than trusting the mutation's exit status. The
    // question the caller actually needs answered is "is it bound NOW", and a
    // command that succeeded but had no effect must not read as success.
    let bound = run_busctl(
        &busctl,
        &[
            "call",
            "org.fedoraproject.FirewallD1",
            "/org/fedoraproject/FirewallD1",
            "org.fedoraproject.FirewallD1.zone",
            "queryInterface",
            "ss",
            "",
            spec.interface.as_str(),
        ],
    )
    .ok()
    .and_then(|out| {
        if out.contains("true") {
            Some(true)
        } else if out.contains("false") {
            Some(false)
        } else {
            None
        }
    });

    let posture = FirewalldPosture {
        presence,
        default_zone,
        interface_bound: bound,
    };
    Ok(PrivilegedCommandOutput {
        status: 0,
        stdout: posture.encode(),
        stderr: String::new(),
    })
}

/// Resolve `busctl` from a fixed private candidate list.
///
/// Deliberately NOT a nameable `PrivilegedCommandProgram`: the daemon must never
/// be able to ask the helper to run `busctl` with arguments of its choosing, so
/// the only argv that ever reaches it are the constants above.
#[cfg(not(windows))]
fn resolve_busctl_binary() -> Result<PathBuf, String> {
    for candidate in ["/usr/bin/busctl", "/bin/busctl"] {
        let path = Path::new(candidate);
        if path.exists()
            && let Ok(validated) = validate_privileged_program_binary(path, "busctl")
        {
            return Ok(validated);
        }
    }
    Err("busctl not available for firewalld zone management".to_owned())
}

#[cfg(not(windows))]
fn run_busctl(busctl: &Path, args: &[&str]) -> Result<String, String> {
    let mut argv: Vec<&str> = vec!["--system", "--json=short"];
    argv.extend_from_slice(args);
    let output = std::process::Command::new(busctl)
        .args(&argv)
        .output()
        .map_err(|err| format!("busctl invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "busctl call failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Extract the first string payload from a `busctl --json=short` reply.
#[cfg(not(windows))]
fn extract_busctl_string(payload: &str) -> Option<String> {
    let marker = "\"data\":[";
    let start = payload.find(marker)? + marker.len();
    let rest = &payload[start..];
    let open = rest.find('"')? + 1;
    let rest = &rest[open..];
    let close = rest.find('"')?;
    let value = &rest[..close];
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Refuse to touch anything that is not a virtual network device.
///
/// A tunnel this daemon created lives under `devices/virtual/net/` in sysfs; a
/// physical NIC does not. Binding a physical interface is never something this
/// builtin should do, so it is refused at the boundary rather than trusted to
/// never be requested.
#[cfg(not(windows))]
fn require_virtual_network_device(interface: &str) -> Result<(), String> {
    let link = std::fs::canonicalize(format!("/sys/class/net/{interface}"))
        .map_err(|err| format!("interface {interface:?} not present in sysfs: {err}"))?;
    let path = link.to_string_lossy();
    if !path.contains("devices/virtual/net/") {
        return Err(format!(
            "refusing firewalld zone bind for non-virtual interface {interface:?}"
        ));
    }
    Ok(())
}

/// Path of the root-only spool directory the helper writes rendered `pf`
/// rulesets into. Lives under `/var/run` (a root-owned system directory a
/// non-root user cannot write to), so the helper-owned, `O_EXCL`-created temp
/// inside it cannot be pre-planted or symlink-swapped by an unprivileged
/// attacker.
#[cfg(unix)]
const MACOS_PF_SPOOL_DIR: &str = "/var/run/rustynet-pf";

/// Render-to-load tail for the macOS pf builtin: own a root-only temp file and
/// run `pfctl` against the helper-derived anchor. Unix-only; fails closed
/// elsewhere.
///
/// `pub(crate)` rather than private because there is a SECOND root
/// `pfctl -f` in this tree: the macOS exit-killswitch precedence validator has
/// to restore the anchor's baseline rules after deliberately tampering with
/// them (PF-10). That path had its own `write_restore_file` doing a plain
/// `fs::write` to a predictable `$TMPDIR` name — no `O_EXCL`, no `O_NOFOLLOW`,
/// no mode, no ownership check — and then handed the path to a root
/// `pfctl -f`. Sharing this function instead of hardening that copy is
/// deliberate: artifact custody for a root `pfctl -f` should have exactly one
/// implementation, or the two drift and only the audited one stays correct.
#[cfg(unix)]
pub(crate) fn load_macos_pf_anchor(anchor: &str, rules: &str) -> Result<(), String> {
    let dir = ensure_macos_pf_spool_dir()?;
    let path = write_root_owned_pf_temp(&dir, rules)?;
    let result = run_macos_pfctl_load(anchor, &path);
    let _ = fs::remove_file(&path);
    result
}

#[cfg(not(unix))]
pub(crate) fn load_macos_pf_anchor(anchor: &str, rules: &str) -> Result<(), String> {
    let _ = (anchor, rules);
    Err("macOS pf anchor load is only supported on Unix".to_owned())
}

/// Create (if absent) and verify the root-only pf spool directory. Fails closed
/// unless it is a real directory (not a symlink), root-owned, and not
/// group/other accessible.
#[cfg(unix)]
fn ensure_macos_pf_spool_dir() -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let dir = PathBuf::from(MACOS_PF_SPOOL_DIR);
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(format!(
                "create macOS pf spool dir {}: {err}",
                dir.display()
            ));
        }
    }
    let meta = fs::symlink_metadata(&dir)
        .map_err(|err| format!("stat macOS pf spool dir {}: {err}", dir.display()))?;
    if !meta.file_type().is_dir() {
        return Err(format!(
            "macOS pf spool dir {} must be a directory (not a symlink)",
            dir.display()
        ));
    }
    if meta.uid() != 0 {
        return Err(format!(
            "macOS pf spool dir {} must be root-owned (uid={})",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "macOS pf spool dir {} must not be group/other accessible ({:03o})",
            dir.display(),
            meta.mode() & 0o777
        ));
    }
    Ok(dir)
}

/// Write `rules` to a fresh, unpredictably-named, `0600` file in `dir`, opened
/// `O_CREAT|O_EXCL` so any pre-existing inode (including a symlink) aborts the
/// open. The helper owns this file end-to-end; the daemon never sees the path.
#[cfg(unix)]
fn write_root_owned_pf_temp(dir: &Path, rules: &str) -> Result<PathBuf, String> {
    use rand::TryRngCore;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|err| format!("pf rules tempfile nonce CSPRNG unavailable: {err}"))?;
    let mut nonce = String::with_capacity(nonce_bytes.len() * 2);
    for byte in nonce_bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut nonce, "{byte:02x}");
    }
    let path = dir.join(format!("pf-{}-{nonce}.conf", std::process::id()));
    // Best-effort sweep of a temp leaked by a crashed prior run; the O_EXCL open
    // below is the real guard against a hostile pre-plant.
    let _ = fs::remove_file(&path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|err| format!("create pf rules temp {}: {err}", path.display()))?;
    file.write_all(rules.as_bytes()).map_err(|err| {
        let _ = fs::remove_file(&path);
        format!("write pf rules temp {}: {err}", path.display())
    })?;
    file.flush()
        .map_err(|err| format!("flush pf rules temp {}: {err}", path.display()))?;
    Ok(path)
}

/// Parse-check (`-n`) then load (`-f`) the rendered ruleset into the
/// helper-derived `anchor`. The anchor and path are helper-controlled — never
/// daemon-supplied — so this internal invocation is constructed entirely from
/// trusted values and intentionally does NOT route through `validate_pfctl_args`
/// (which no longer accepts `-f` from the boundary).
#[cfg(unix)]
fn run_macos_pfctl_load(anchor: &str, path: &Path) -> Result<(), String> {
    let binary = PrivilegedCommandProgram::Pfctl.resolve_binary()?;
    let path_str = path
        .to_str()
        .ok_or_else(|| "pf rules temp path is not valid UTF-8".to_owned())?;
    run_macos_pfctl(&binary, &["-n", "-a", anchor, "-f", path_str])?;
    run_macos_pfctl(&binary, &["-a", anchor, "-f", path_str])
}

#[cfg(unix)]
fn run_macos_pfctl(binary: &Path, args: &[&str]) -> Result<(), String> {
    let owned: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
    let output = run_privileged_subprocess(
        binary,
        &owned,
        Duration::from_millis(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS),
    )?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "pfctl {:?} failed: status={:?} stderr={}",
        args,
        output.status.code(),
        truncate_lossy(&output.stderr, MAX_OUTPUT_BYTES)
    ))
}

/// If `program` is an in-helper builtin, validate its arguments and run the
/// in-process handler, returning the captured output. Returns `None` for
/// programs that exec an external binary, so the helper-less direct path can
/// fall through to its exec logic. This keeps the builtin behaving identically
/// whether or not a privilege-separated helper is in use.
pub(crate) fn try_execute_builtin_program(
    program: PrivilegedCommandProgram,
    args: &[&str],
) -> Option<Result<PrivilegedCommandOutput, String>> {
    if !program.is_builtin() {
        return None;
    }
    if let Err(err) = validate_request(program, args) {
        return Some(Err(err));
    }
    Some(execute_builtin(program, args))
}

#[cfg(not(windows))]
fn validate_privileged_program_binary(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "{label} binary path must be absolute: {}",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|err| format!("{label} binary canonicalization failed: {err}"))?;
    let metadata =
        fs::metadata(&canonical).map_err(|err| format!("{label} binary metadata failed: {err}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} binary path must be a regular file: {}",
            canonical.display()
        ));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o111 == 0 {
        return Err(format!(
            "{label} binary is not executable: {} ({mode:03o})",
            canonical.display()
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "{label} binary must not be group/other writable: {} ({mode:03o})",
            canonical.display()
        ));
    }
    let owner_uid = metadata.uid();
    if owner_uid != 0 {
        return Err(format!(
            "{label} binary must be root-owned: {} (uid={owner_uid})",
            canonical.display()
        ));
    }
    Ok(canonical)
}

// NOTE: a `#[cfg(windows)]` `validate_privileged_program_binary` stub previously
// lived here to satisfy the (now `#[cfg(not(windows))]`-gated) `resolve_binary`
// reference on Windows. With binary resolution and the exec path gated to unix,
// the Windows stub had no caller and was dead code, so it was removed.

// Privileged subprocess exec + its output helpers run only inside the unix
// helper server; Windows never reaches the exec path (IPC fails closed first).
#[cfg(not(windows))]
fn run_privileged_subprocess(
    binary: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait().map_err(|err| err.to_string())? {
            Some(_status) => {
                return child
                    .wait_with_output()
                    .map_err(|err| format!("wait for privileged subprocess failed: {err}"));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {} ms", timeout.as_millis()));
            }
            None => sleep(Duration::from_millis(10)),
        }
    }
}

#[cfg(not(windows))]
fn exit_status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

#[cfg(not(windows))]
fn truncate_lossy(bytes: &[u8], max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        return String::from_utf8_lossy(bytes).to_string();
    }
    let mut out = String::from_utf8_lossy(&bytes[..max_bytes]).to_string();
    out.push_str("...[truncated]");
    out
}

pub fn validate_request(program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), String> {
    if args.len() > MAX_ARGS {
        return Err(format!(
            "too many arguments for privileged command {program}",
        ));
    }
    if args.is_empty() {
        return Err(format!(
            "missing arguments for privileged command {program}",
        ));
    }
    for arg in args {
        if arg.is_empty() {
            return Err(format!("empty argument in privileged command {program}"));
        }
        if arg.len() > MAX_ARG_BYTES {
            return Err(format!("argument too long in privileged command {program}",));
        }
    }
    match program {
        PrivilegedCommandProgram::Ip => validate_ip_args(args),
        PrivilegedCommandProgram::Nft => validate_nft_args(args),
        PrivilegedCommandProgram::Wg => validate_wg_args(args),
        PrivilegedCommandProgram::Sysctl => validate_sysctl_args(args),
        PrivilegedCommandProgram::Ifconfig => validate_ifconfig_args(args),
        PrivilegedCommandProgram::Route => validate_route_args(args),
        PrivilegedCommandProgram::Pfctl => validate_pfctl_args(args),
        PrivilegedCommandProgram::WireguardGo => validate_wireguard_go_args(args),
        PrivilegedCommandProgram::Kill => validate_kill_args(args),
        PrivilegedCommandProgram::DnsFailclosedFile => validate_dns_failclosed_file_args(args),
        PrivilegedCommandProgram::MacosPfLoad => validate_macos_pf_load_args(args),
        PrivilegedCommandProgram::LinuxFirewalldZone => validate_linux_firewalld_zone_args(args),
    }
}

/// Validate the `linux-firewalld-zone` builtin. Decode success IS the
/// validation, exactly as for `macos-pf-load`: the grammar is two `key=value`
/// tokens (`op`, `interface`) with duplicate and unknown-key rejection, the op
/// is an exact match against three literals with no default arm, and the
/// interface must be a plausible device name that is not the loopback.
///
/// There is no zone token to validate, because the caller cannot express one.
fn validate_linux_firewalld_zone_args(args: &[&str]) -> Result<(), String> {
    crate::linux_firewalld_zone::FirewalldZoneSpec::decode(args).map(|_| ())
}

/// Validate the `macos-pf-load` builtin: the arguments must decode into a
/// well-formed [`crate::macos_pf_load_spec::MacosPfLoadSpec`]. `decode` re-parses
/// every field through a typed validator and bounds list lengths, so a
/// successful decode IS the validation — the daemon can choose only spec
/// parameters, never inject rule text, a file path, or an anchor name.
fn validate_macos_pf_load_args(args: &[&str]) -> Result<(), String> {
    crate::macos_pf_load_spec::MacosPfLoadSpec::decode(args).map(|_| ())
}

/// Validate the `dns-failclosed-file` builtin: EXACTLY one argument, and that
/// argument must be one of the four reviewed selectors. The selector is the only
/// value that crosses the privileged boundary — the helper supplies the path and
/// content — so this is the entire attack surface of the builtin.
fn validate_dns_failclosed_file_args(args: &[&str]) -> Result<(), String> {
    match args {
        [selector] if crate::linux_dns_protect::is_valid_dns_failclosed_file_selector(selector) => {
            Ok(())
        }
        _ => Err(
            "unsupported dns-failclosed-file argument schema (expected exactly one reviewed selector)"
                .to_owned(),
        ),
    }
}

fn is_safe_token(value: &str) -> bool {
    value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | ',' | '=' | '+')
    })
}

#[cfg(all(test, not(windows)))]
fn is_nft_token(value: &str) -> bool {
    matches!(value, "{" | "}" | ";" | "!=") || is_safe_token(value)
}

/// Accept an `ip link set mtu` value only inside the audited bring-up range.
///
/// Bounded by `rustynet_backend_wireguard`'s own constants so the helper and
/// the backend can never drift apart: the ceiling is the audited default, the
/// floor is the smallest tunnel MTU that still clears a 1280-byte outer hop.
/// Anything outside the range -- or not a plain u16 -- is refused, so this
/// stays a narrow capability grant rather than "any numeric MTU".
fn is_bringup_tunnel_mtu_token(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|mtu| {
        (rustynet_backend_wireguard::MIN_BRINGUP_TUNNEL_MTU
            ..=rustynet_backend_wireguard::SAFE_BRINGUP_TUNNEL_MTU)
            .contains(&mtu)
    })
}

fn is_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn is_path_token(value: &str) -> bool {
    if !value.starts_with('/') || !is_safe_token(value) {
        return false;
    }
    // Reject parent-directory traversal in any segment so that an attacker who
    // can speak the IPC cannot redirect a privileged binary (wg, pfctl, etc.)
    // at a file outside the path the daemon expected.
    !value.split('/').any(|segment| segment == "..")
}

fn is_u16_token(value: &str) -> bool {
    value
        .parse::<u16>()
        .map(|parsed| parsed != 0)
        .unwrap_or(false)
}

fn is_u32_token(value: &str) -> bool {
    value.parse::<u32>().is_ok()
}

fn is_ipv4_or_ipv6(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn is_cidr_token(value: &str) -> bool {
    let Some((base, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(addr) = base.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_value) = prefix.parse::<u8>() else {
        return false;
    };
    match addr {
        IpAddr::V4(_) => prefix_value <= 32,
        IpAddr::V6(_) => prefix_value <= 128,
    }
}

fn is_wg_public_key_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
}

fn is_wg_endpoint_token(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || !is_u16_token(port) {
        return false;
    }
    host.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '-' | '[' | ']'))
}

fn is_allowed_ips_token(value: &str) -> bool {
    !value.is_empty() && value.split(',').all(is_cidr_token)
}

/// `wg set ... persistent-keepalive <interval>` interval token (FIS-0015).
///
/// Deliberately NOT [`is_u16_token`]: that helper rejects `0` because a port of
/// zero is meaningless, whereas `0` is wg's documented "disable keepalive"
/// value and `PeerConfig::persistent_keepalive_secs` is an `Option<u16>` whose
/// `Some(0)` renders exactly that. Rejecting it here would reproduce the very
/// failure this arm exists to prevent — a fail-closed denial of peer
/// configuration rather than a degraded keepalive.
///
/// The permitted domain is therefore wg's own: decimal `0..=65535`. Requiring
/// every byte to be an ASCII digit additionally rejects the sign-prefixed forms
/// Rust's integer parser would otherwise accept (`+21`), keeping the token
/// canonical.
fn is_wg_keepalive_secs_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok()
}

fn is_anchor_name_token(value: &str) -> bool {
    if !(value.starts_with("com.apple/rustynet_g")
        || value == "com.rustynet/blind_exit"
        || value == "com.rustynet/nat")
    {
        return false;
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.'))
    {
        return false;
    }
    // Reject parent-directory traversal segments so the anchor name cannot
    // redirect pfctl outside the rustynet anchor namespace.
    !value.split('/').any(|segment| segment == "..")
}

fn is_owned_nft_table_token(value: &str) -> bool {
    (value.starts_with("rustynet_g") || value.starts_with("rustynet_nat_g"))
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn is_owned_failclosed_table_token(value: &str) -> bool {
    value.starts_with("rustynet_g")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn is_owned_nat_table_token(value: &str) -> bool {
    value.starts_with("rustynet_nat_g")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

/// True ONLY for the dedicated protected-mode DNS-redirect table
/// (`rustynet_g<gen>_dns`, built by `linux_dns_protect`). Deliberately distinct
/// from `is_owned_failclosed_table_token` (the filter-drop killswitch tables)
/// and `is_owned_nat_table_token` (the exit masquerade tables): the
/// `nat`/`redirect` chain+rule are permitted ONLY on this table, so a redirect
/// can never be slipped into the killswitch's default-deny filter table.
fn is_owned_dns_redirect_table_token(value: &str) -> bool {
    value.starts_with("rustynet_g")
        && value.ends_with("_dns")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

/// True for an nft `redirect to :<port>` target that stays on the local host:
/// a bare `:<port>` with a non-zero port and no address. The protected-mode DNS
/// redirect points loopback `:53` at the rustynet resolver's unprivileged bind
/// port; an address-bearing target (e.g. `1.2.3.4:53`) is rejected so the rule
/// can only ever redirect to a local socket.
fn is_loopback_dns_redirect_target(value: &str) -> bool {
    value
        .strip_prefix(':')
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0)
}

fn is_nft_family_token(value: &str) -> bool {
    matches!(value, "inet" | "ip" | "ip6")
}

fn is_nft_chain_token(value: &str) -> bool {
    matches!(
        value,
        "killswitch" | "forward" | "input" | "output" | "prerouting" | "postrouting"
    )
}

fn is_nft_daddr_family_token(value: &str) -> bool {
    matches!(value, "ip" | "ip6")
}

fn is_cidr_for_nft_family(cidr: &str, family: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(addr) = base.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_value) = prefix.parse::<u8>() else {
        return false;
    };
    match (family, addr) {
        ("ip", IpAddr::V4(_)) => prefix_value <= 32,
        ("ip6", IpAddr::V6(_)) => prefix_value <= 128,
        _ => false,
    }
}

fn is_exact_ip_for_nft_family(address: &str, family: &str) -> bool {
    match family {
        "ip" => address.parse::<Ipv4Addr>().is_ok(),
        "ip6" => address.parse::<Ipv6Addr>().is_ok(),
        _ => false,
    }
}

fn validate_nft_add_chain_args(args: &[&str]) -> Result<(), String> {
    match args {
        [
            "add",
            "chain",
            "inet",
            table,
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
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "chain",
            "inet",
            table,
            "forward",
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "0",
            ";",
            "policy",
            "drop",
            ";",
            "}",
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "chain",
            "ip",
            table,
            "postrouting",
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "100",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ] if is_owned_nat_table_token(table) => Ok(()),
        // Protected-mode DNS fail-closed: a nat/output chain on the dedicated
        // DNS-redirect table ONLY (scoped by is_owned_dns_redirect_table_token).
        // Lets `linux_dns_protect`'s loopback :53 -> resolver redirect install
        // without permitting nat on the filter-drop killswitch tables.
        [
            "add",
            "chain",
            "inet",
            table,
            "dns_redirect",
            "{",
            "type",
            "nat",
            "hook",
            "output",
            "priority",
            "dstnat",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ] if is_owned_dns_redirect_table_token(table) => Ok(()),
        _ => Err("unsupported nft add chain argument schema".to_owned()),
    }
}

/// Rejections name the offending argv, deliberately.
///
/// A refusal that says only "unsupported nft add rule argument schema" tells an
/// operator that the privileged boundary held, and nothing about WHAT was
/// refused — which left a real defect (an `entry`-role rule shape this allowlist
/// does not carry) diagnosable only by reading the daemon source and guessing.
///
/// Safe for THESE arguments specifically, and the scope is the point: `nft` rule
/// argv carries table/chain names, addresses, ports, protocols and marks — rule
/// SHAPE, never key material. `wg` argv can carry private keys, so its validator
/// must NOT copy this; it is left disclosing nothing.
fn validate_nft_add_rule_args(args: &[&str]) -> Result<(), String> {
    match args {
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "oifname",
            "lo",
            "accept",
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "ct",
            "state",
            "established,related",
            "accept",
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "oifname",
            interface,
            "accept",
        ] if is_owned_failclosed_table_token(table) && is_interface_name(interface) => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "ct",
            "state",
            "established,related",
            "accept",
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "iifname",
            incoming_interface,
            "oifname",
            outgoing_interface,
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(incoming_interface)
            && is_interface_name(outgoing_interface) =>
        {
            Ok(())
        }
        // As above, with a `counter` statement. The entry/relay hop emits this
        // shape (`iifname rustynet0 oifname rustynet0 counter accept`) so a
        // two-hop path can be observed; without this arm the helper refused it,
        // the daemon failed closed, and live_two_hop_validation could not run
        // (QH-45).
        //
        // This grants NO additional authority, which is why it is a separate,
        // equally-narrow arm rather than a loosening of the one above. `counter`
        // is a pure nftables statement: it increments packet/byte counters and
        // affects neither the match nor the verdict. The semantically identical
        // rule WITHOUT `counter` is already permitted directly above, under the
        // same three constraints — owned fail-closed table, and both interface
        // names well-formed — all of which are re-applied here unchanged.
        [
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "iifname",
            incoming_interface,
            "oifname",
            outgoing_interface,
            "counter",
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(incoming_interface)
            && is_interface_name(outgoing_interface)
            // Hairpin only. The emitter passes one interface into both slots, so
            // requiring equality matches the caller exactly and keeps this arm a
            // SHAPE rather than a pattern. It reduces no authority — the sibling
            // arm above still grants the more general A→B form without `counter`
            // — so this is intent, not a boundary tightening; claiming otherwise
            // would overstate it.
            && incoming_interface == outgoing_interface =>
        {
            Ok(())
        }
        // blind_exit mesh-scoped final-hop allow: forward from the tunnel to
        // the egress interface ONLY when the source address is inside the
        // bounded mesh CIDR (`ip`/`ip6 saddr <cidr>`). The daemon
        // (`linux_blind_exit`) additionally pins `<cidr>` to a private/CGNAT/ULA
        // range before this is reached; here we enforce the argv shape +
        // family/CIDR agreement as defense-in-depth.
        [
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "iifname",
            incoming_interface,
            "oifname",
            outgoing_interface,
            family,
            "saddr",
            cidr,
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(incoming_interface)
            && is_interface_name(outgoing_interface)
            && is_nft_daddr_family_token(family)
            && is_cidr_for_nft_family(cidr, family) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "oifname",
            interface,
            family,
            "daddr",
            address,
            "udp",
            "dport",
            port,
            "accept",
            "comment",
            "rustynet_traversal_bootstrap",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(interface)
            && is_nft_daddr_family_token(family)
            && is_exact_ip_for_nft_family(address, family)
            && is_u16_token(port) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            family,
            "daddr",
            cidr,
            "tcp",
            "dport",
            "22",
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_nft_daddr_family_token(family)
            && is_cidr_for_nft_family(cidr, family) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            family,
            "daddr",
            cidr,
            "tcp",
            "sport",
            "22",
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_nft_daddr_family_token(family)
            && is_cidr_for_nft_family(cidr, family) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            protocol,
            "dport",
            "53",
            "oifname",
            "!=",
            interface,
            "drop",
        ] if is_owned_failclosed_table_token(table)
            && matches!(*protocol, "udp" | "tcp")
            && is_interface_name(interface) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            protocol,
            "dport",
            "53",
            "accept",
        ] if is_owned_failclosed_table_token(table) && matches!(*protocol, "udp" | "tcp") => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "counter",
            "drop",
            "comment",
            "rustynet_fail_closed_drop",
        ] if is_owned_failclosed_table_token(table) => Ok(()),
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "oifname",
            interface,
            "udp",
            "dport",
            port,
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(interface)
            && is_u16_token(port) =>
        {
            Ok(())
        }
        // Same shape, matched on the SOURCE port. Outbound WireGuard leaves the
        // daemon's bound socket with the listen port as its source, whatever
        // port the peer's NAT mapped it to; without this a peer reached at its
        // server-reflexive candidate is unreachable and NAT traversal cannot
        // complete. Bounded identically to the dport form: an owned fail-closed
        // table, a real interface name, and a u16 port.
        [
            "add",
            "rule",
            "inet",
            table,
            "killswitch",
            "oifname",
            interface,
            "udp",
            "sport",
            port,
            "accept",
        ] if is_owned_failclosed_table_token(table)
            && is_interface_name(interface)
            && is_u16_token(port) =>
        {
            Ok(())
        }
        [
            "add",
            "rule",
            "ip",
            table,
            "postrouting",
            "oifname",
            interface,
            "masquerade",
        ] if is_owned_nat_table_token(table) && is_interface_name(interface) => Ok(()),
        [
            "add",
            "rule",
            "ip",
            table,
            "postrouting",
            "iifname",
            incoming_interface,
            "oifname",
            outgoing_interface,
            "masquerade",
        ] if is_owned_nat_table_token(table)
            && is_interface_name(incoming_interface)
            && is_interface_name(outgoing_interface) =>
        {
            Ok(())
        }
        // As above, with a `counter` statement — the NAT half of the same
        // entry/relay hairpin. Adding only the `forward` counter arm left this
        // one refused, so the run simply died one step later in
        // `apply_nat_forwarding` instead of `apply_firewall_killswitch`, with the
        // error string changing and nothing else. Both emitters are gated by the
        // same `allow_tunnel_relay_forward` flag, so they always appear together.
        //
        // Grants no authority the arm above did not: same table and interface
        // guards, same fixed arity, and `counter` affects neither match nor
        // verdict. Hairpin-only for the same reason as the forward arm — the
        // emitter passes one interface into both slots.
        [
            "add",
            "rule",
            "ip",
            table,
            "postrouting",
            "iifname",
            incoming_interface,
            "oifname",
            outgoing_interface,
            "counter",
            "masquerade",
        ] if is_owned_nat_table_token(table)
            && is_interface_name(incoming_interface)
            && is_interface_name(outgoing_interface)
            && incoming_interface == outgoing_interface =>
        {
            Ok(())
        }
        // Protected-mode DNS fail-closed redirect: loopback (127.0.0.1) :53 ->
        // the rustynet resolver's local bind port, udp+tcp, on the dedicated DNS
        // table ONLY. Tightly bounded: fixed daddr 127.0.0.1, fixed dport 53,
        // matching l4proto, and a local-only `:<port>` redirect target — so it
        // can only ever divert loopback DNS to a local socket.
        [
            "add",
            "rule",
            "inet",
            table,
            "dns_redirect",
            "meta",
            "l4proto",
            proto,
            "ip",
            "daddr",
            "127.0.0.1",
            proto2,
            "dport",
            "53",
            "redirect",
            "to",
            target,
        ] if is_owned_dns_redirect_table_token(table)
            && matches!(*proto, "udp" | "tcp")
            && proto == proto2
            && is_loopback_dns_redirect_target(target) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "unsupported nft add rule argument schema: {}",
            args.join(" ")
        )),
    }
}

fn validate_ip_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-V"] => Ok(()),
        ["link", "add", "dev", interface, "type", "wireguard"] if is_interface_name(interface) => {
            Ok(())
        }
        [
            "tuntap",
            "add",
            "dev",
            interface,
            "mode",
            "tun",
            "user",
            owner_uid,
            "group",
            owner_gid,
        ] if is_interface_name(interface) && is_u32_token(owner_uid) && is_u32_token(owner_gid) => {
            Ok(())
        }
        ["link", "set", "up", "dev", interface] if is_interface_name(interface) => Ok(()),
        ["link", "set", "down", "dev", interface] if is_interface_name(interface) => Ok(()),
        // FIS-0027 Phase 2 (fef40bb) made the Linux WireGuard bring-up set a safe
        // tunnel MTU (`ip link set mtu <mtu> dev <iface>`) right after interface
        // creation. This was originally matched as an EXACT LITERAL because the
        // only caller sent one constant, with a note to widen it to a validated
        // bounded range once the value became dynamic.
        //
        // That time has come: a NAT-traversed path can ride a carrier with a
        // smaller MTU than the 1500-byte underlay the default assumes, so the
        // bring-up value is now resolved per host and can legitimately be lower.
        // The range is still tightly bounded and, critically, its CEILING is the
        // audited default -- so this can only ever make a tunnel more
        // conservative, never grant a larger MTU than the exact-literal form
        // allowed. A compromised daemon gains no reach it did not already have.
        ["link", "set", "mtu", mtu, "dev", interface]
            if is_bringup_tunnel_mtu_token(mtu) && is_interface_name(interface) =>
        {
            Ok(())
        }
        ["link", "del", "dev", interface] if is_interface_name(interface) => Ok(()),
        ["address", "add", cidr, "dev", interface]
            if is_cidr_token(cidr) && is_interface_name(interface) =>
        {
            Ok(())
        }
        ["route", "del", cidr, "dev", interface]
            if is_cidr_token(cidr) && is_interface_name(interface) =>
        {
            Ok(())
        }
        ["route", "replace", cidr, "dev", interface]
            if is_cidr_token(cidr) && is_interface_name(interface) =>
        {
            Ok(())
        }
        ["route", "replace", cidr, "dev", interface, "table", "51820"]
            if is_cidr_token(cidr) && is_interface_name(interface) =>
        {
            Ok(())
        }
        ["-4", "route", "show", "table", "51820"] => Ok(()),
        ["-6", "route", "show", "table", "51820"] => Ok(()),
        [
            "-6",
            "route",
            "replace",
            cidr,
            "dev",
            interface,
            "table",
            "51820",
        ] if is_cidr_token(cidr) && is_interface_name(interface) => Ok(()),
        ["route", "flush", "table", "51820"] => Ok(()),
        ["rule", "show"] => Ok(()),
        ["-4", "route", "get", target] if target.parse::<std::net::Ipv4Addr>().is_ok() => Ok(()),
        ["-6", "route", "flush", "table", "51820"] => Ok(()),
        ["route", "get", target] if is_ipv4_or_ipv6(target) => Ok(()),
        ["-6", "route", "get", target] if target.parse::<std::net::Ipv6Addr>().is_ok() => Ok(()),
        ["rule", "del", "table", "51820"] => Ok(()),
        ["rule", "del", "priority", priority, "table", "51820"] if is_u32_token(priority) => Ok(()),
        ["rule", "add", "priority", priority, "table", "51820"] if is_u32_token(priority) => Ok(()),
        _ => Err("unsupported ip argument schema".to_owned()),
    }
}

fn validate_nft_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["--version"] => Ok(()),
        ["list", "tables"] => Ok(()),
        ["list", "table", family, table]
            if is_nft_family_token(family) && is_owned_nft_table_token(table) =>
        {
            Ok(())
        }
        ["list", "chain", family, table, chain]
            if is_nft_family_token(family)
                && is_owned_nft_table_token(table)
                && is_nft_chain_token(chain) =>
        {
            Ok(())
        }
        ["add", "table", family, table]
            if is_nft_family_token(family) && is_owned_nft_table_token(table) =>
        {
            Ok(())
        }
        ["delete", "table", family, table]
            if is_nft_family_token(family) && is_owned_nft_table_token(table) =>
        {
            Ok(())
        }
        // Flush the `forward` chain only (keeps the chain's `policy drop`),
        // used by the blind_exit hardened-egress path to clear the regular-exit
        // unrestricted tunnel->egress allow before re-authoring the
        // mesh-scoped final-hop rule. Restricted to `forward` so it can never
        // be used to clear the killswitch chain.
        ["flush", "chain", "inet", table, "forward"] if is_owned_failclosed_table_token(table) => {
            Ok(())
        }
        _ if args.starts_with(&["add", "chain"]) => validate_nft_add_chain_args(args),
        _ if args.starts_with(&["add", "rule"]) => validate_nft_add_rule_args(args),
        _ => Err("unsupported nft argument schema".to_owned()),
    }
}

fn validate_wg_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["--version"] => Ok(()),
        ["show", interface, "latest-handshakes"] if is_interface_name(interface) => Ok(()),
        [
            "set",
            interface,
            "private-key",
            private_key_path,
            "listen-port",
            port,
        ] if is_interface_name(interface)
            && is_path_token(private_key_path)
            && is_u16_token(port) =>
        {
            Ok(())
        }
        ["set", interface, "private-key", private_key_path]
            if is_interface_name(interface) && is_path_token(private_key_path) =>
        {
            Ok(())
        }
        [
            "set",
            interface,
            "peer",
            public_key,
            "endpoint",
            endpoint,
            "allowed-ips",
            allowed_ips,
        ] if is_interface_name(interface)
            && is_wg_public_key_token(public_key)
            && is_wg_endpoint_token(endpoint)
            && is_allowed_ips_token(allowed_ips) =>
        {
            Ok(())
        }
        // Same peer-configure shape with the FIS-0015 adaptive-keepalive tail.
        // `configure_peer` appends `persistent-keepalive <interval>` in all
        // three command backends the moment
        // `PeerConfig::persistent_keepalive_secs` is `Some`, so without this arm
        // switching the adaptive-keepalive rollout on would fail peer
        // configuration outright on the Linux and macOS production backends
        // (both validate here, client-side, before the helper socket) rather
        // than merely forgo the keepalive.
        [
            "set",
            interface,
            "peer",
            public_key,
            "endpoint",
            endpoint,
            "allowed-ips",
            allowed_ips,
            "persistent-keepalive",
            keepalive_secs,
        ] if is_interface_name(interface)
            && is_wg_public_key_token(public_key)
            && is_wg_endpoint_token(endpoint)
            && is_allowed_ips_token(allowed_ips)
            && is_wg_keepalive_secs_token(keepalive_secs) =>
        {
            Ok(())
        }
        // Endpoint-only re-point, with no `allowed-ips` tail: the shape
        // `update_peer_endpoint` emits when NAT traversal promotes a peer to a
        // directly reachable address. It deliberately does not carry the
        // keepalive tail, because no backend emits that combination.
        ["set", interface, "peer", public_key, "endpoint", endpoint]
            if is_interface_name(interface)
                && is_wg_public_key_token(public_key)
                && is_wg_endpoint_token(endpoint) =>
        {
            Ok(())
        }
        ["set", interface, "peer", public_key, "remove"]
            if is_interface_name(interface) && is_wg_public_key_token(public_key) =>
        {
            Ok(())
        }
        _ => Err("unsupported wg argument schema".to_owned()),
    }
}

fn validate_sysctl_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["--version"] => Ok(()),
        ["-w", "net.ipv4.ip_forward=1" | "net.ipv4.ip_forward=0"] => Ok(()),
        [
            "-w",
            "net.ipv6.conf.all.disable_ipv6=1" | "net.ipv6.conf.all.disable_ipv6=0",
        ] => Ok(()),
        // macOS IPv4/IPv6 forwarding toggles for the regular exit NAT
        // dataplane. The read form (`-n net.inet{,6}.ip{,6}.forwarding`) caches
        // the prior value for fail-closed restore on teardown. The exit enables
        // the forwarding family matching its mesh prefix (v4 mesh -> IPv4, v6
        // mesh -> IPv6). Only the exact `=1`/`=0` writes are permitted —
        // arbitrary values stay default-denied.
        [
            "-w",
            "net.inet.ip.forwarding=1" | "net.inet.ip.forwarding=0",
        ] => Ok(()),
        ["-n", "net.inet.ip.forwarding"] => Ok(()),
        [
            "-w",
            "net.inet6.ip6.forwarding=1" | "net.inet6.ip6.forwarding=0",
        ] => Ok(()),
        ["-n", "net.inet6.ip6.forwarding"] => Ok(()),
        _ => Err("unsupported sysctl argument schema".to_owned()),
    }
}

fn validate_ifconfig_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-l"] => Ok(()),
        [interface, "up"] if is_interface_name(interface) => Ok(()),
        [interface, "down"] if is_interface_name(interface) => Ok(()),
        [
            interface,
            "inet",
            local_ip,
            peer_ip,
            "netmask",
            "255.255.255.255",
        ] if is_interface_name(interface)
            && is_ipv4_or_ipv6(local_ip)
            && is_ipv4_or_ipv6(peer_ip) =>
        {
            Ok(())
        }
        _ => Err("unsupported ifconfig argument schema".to_owned()),
    }
}

fn validate_route_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-n", "get", "default"] => Ok(()),
        // Read-only per-endpoint route lookup issued by the macOS WireGuard
        // backend's on-link/off-link probe
        // (`macos_endpoint_needs_gateway_bypass`): `route -n get
        // -inet|-inet6 <endpoint>`. It installs no state; it only reads the
        // current routing decision for a literal IP so the backend can tell
        // whether a peer's underlay endpoint is reached via the default
        // gateway (off-subnet — needs a /32 bypass installed BEFORE the
        // split-default halves capture it) or on-link (reachable via the
        // intact connected route — bypass must be skipped). Without this
        // schema the helper rejects the probe; the backend then treated
        // every endpoint as on-link and installed the `0.0.0.0/1` +
        // `128.0.0.0/1` halves with no bypass routes at all, which
        // blackholed the WireGuard underlay for every off-subnet peer
        // (observed live: a macOS node in full-tunnel exit mode could not
        // complete a single handshake to its Linux exit peer on a
        // neighbouring UTM subnet).
        ["-n", "get", "-inet" | "-inet6", target] if is_ipv4_or_ipv6(target) => Ok(()),
        [
            "-n",
            "add" | "change",
            "-inet",
            "default",
            "-interface",
            interface,
        ] if is_interface_name(interface) => Ok(()),
        ["-n", "change", "-inet", "default", gateway] if is_ipv4_or_ipv6(gateway) => Ok(()),
        [
            "-n",
            "add",
            "-inet" | "-inet6",
            "-host",
            endpoint,
            gateway,
            "-ifscope",
            interface,
        ] if is_ipv4_or_ipv6(endpoint)
            && is_ipv4_or_ipv6(gateway)
            && is_interface_name(interface) =>
        {
            Ok(())
        }
        // Endpoint bypass route without `-ifscope`. The macOS WireGuard
        // backend installs the per-peer endpoint bypass route in the
        // default (non-scoped) flavor so the daemon's unbound
        // authoritative UDP socket actually consults it; an ifscope'd
        // route is invisible to unbound sockets and lets the encrypted
        // handshake frames loop back into the utun after full-tunnel
        // exit mode flips the default route.
        ["-n", "add", "-inet" | "-inet6", "-host", endpoint, gateway]
            if is_ipv4_or_ipv6(endpoint) && is_ipv4_or_ipv6(gateway) =>
        {
            Ok(())
        }
        ["-n", "delete", "-inet" | "-inet6", "-host", endpoint] if is_ipv4_or_ipv6(endpoint) => {
            Ok(())
        }
        [
            "-n",
            "add",
            "-inet" | "-inet6",
            "-net",
            cidr,
            "-interface",
            interface,
        ] if is_cidr_token(cidr) && is_interface_name(interface) => Ok(()),
        ["-n", "delete", "-inet" | "-inet6", "-net", cidr] if is_cidr_token(cidr) => Ok(()),
        _ => Err("unsupported route argument schema".to_owned()),
    }
}

fn validate_pfctl_args(args: &[&str]) -> Result<(), String> {
    for arg in args {
        if !is_safe_token(arg) {
            return Err(format!("unsupported pfctl token: {arg}"));
        }
    }
    match args {
        ["-E"] => Ok(()),
        ["-s", "info"] => Ok(()),
        ["-s", "Anchors"] => Ok(()),
        ["-a", anchor, "-F", "all"] if is_anchor_name_token(anchor) => Ok(()),
        // NOTE: `-f <path>` / `-n -a <anchor> -f <path>` are DELIBERATELY NOT
        // accepted from the privileged boundary. Loading a daemon-authored rules
        // file let a compromised daemon inject arbitrary `pf` rules (e.g.
        // `pass out quick all`) into the killswitch anchor (audit major #5). All
        // rule loading now goes through the `macos-pf-load` builtin, which
        // re-renders the rule text in the helper from a validated structured
        // spec and owns the temp file + `pfctl -f` itself. Do not re-add a
        // boundary-supplied `-f` arm.
        ["-a", anchor, "-s", "rules"] if is_anchor_name_token(anchor) => Ok(()),
        // Read-only NAT-rule show, used to verify the exit NAT anchor after
        // load (the filter `-s rules` show is empty for a translation anchor).
        ["-a", anchor, "-s", "nat"] if is_anchor_name_token(anchor) => Ok(()),
        _ => Err("unsupported pfctl argument schema".to_owned()),
    }
}

fn validate_wireguard_go_args(args: &[&str]) -> Result<(), String> {
    match args {
        [interface] if is_interface_name(interface) => Ok(()),
        _ => Err("unsupported wireguard-go argument schema".to_owned()),
    }
}

fn validate_kill_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-TERM", pid] if pid.parse::<u32>().map(|value| value > 1).unwrap_or(false) => Ok(()),
        _ => Err("unsupported kill argument schema".to_owned()),
    }
}

#[cfg(not(windows))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return getsockopt(stream, PeerCredentials)
            .ok()
            .map(|cred| cred.uid());
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    return getsockopt(stream, LocalPeerCred)
        .ok()
        .map(|cred| cred.uid());

    #[allow(unreachable_code)]
    None
}

impl fmt::Display for PrivilegedCommandProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        HELPER_FRAME_MAGIC, HELPER_FRAME_TYPE_REQUEST, HELPER_FRAME_TYPE_RESPONSE,
        HELPER_FRAME_VERSION, HelperRequest, HelperResponse, MAX_ARG_BYTES, MAX_ARGS,
        MAX_MESSAGE_BYTES, MAX_PROGRAM_BYTES, PrivilegedCommandProgram, decode_helper_request,
        encode_helper_request, handle_request, is_anchor_name_token, is_nft_token, is_path_token,
        is_safe_token, peer_uid, read_request, read_response_frame, run_privileged_subprocess,
        validate_pfctl_args, validate_privileged_helper_socket_security,
        validate_privileged_program_binary, validate_request, validate_sysctl_args,
        write_request_frame, write_response,
    };

    #[test]
    fn privileged_argv_token_validators_enforce_allowlists() {
        use super::{
            is_cidr_token, is_interface_name, is_owned_nft_table_token, is_wg_public_key_token,
        };

        // Interface names: non-empty, <=15 chars (IFNAMSIZ), alnum + '_' '-'.
        assert!(is_interface_name("rustynet0"));
        assert!(is_interface_name("eth0-1"));
        assert!(!is_interface_name(""));
        assert!(!is_interface_name(&"a".repeat(16)));
        assert!(!is_interface_name("eth 0"));
        assert!(!is_interface_name("eth;rm"));

        // nft table tokens must be rustynet-owned (prefix anchored) and free of
        // any character that could break the argv into a second command.
        assert!(is_owned_nft_table_token("rustynet_g5"));
        assert!(is_owned_nft_table_token("rustynet_nat_g12"));
        assert!(!is_owned_nft_table_token("filter"));
        assert!(!is_owned_nft_table_token("rustynet_g5; nft flush ruleset"));
        assert!(!is_owned_nft_table_token("evil_rustynet_g5"));

        // WireGuard public keys: base64 alphabet, non-empty, <=128.
        assert!(is_wg_public_key_token("abcDEF123+/="));
        assert!(!is_wg_public_key_token(""));
        assert!(!is_wg_public_key_token(&"a".repeat(129)));
        assert!(!is_wg_public_key_token("has space"));
        assert!(!is_wg_public_key_token("semi;colon"));

        // CIDR tokens: parseable base address + in-range family prefix.
        assert!(is_cidr_token("10.0.0.0/8"));
        assert!(is_cidr_token("::/0"));
        assert!(is_cidr_token("fd00::/64"));
        assert!(!is_cidr_token("10.0.0.0")); // no prefix
        assert!(!is_cidr_token("10.0.0.0/33")); // v4 prefix out of range
        assert!(!is_cidr_token("::1/129")); // v6 prefix out of range
        assert!(!is_cidr_token("notanip/8"));
        assert!(!is_cidr_token("10.0.0.0/x"));
    }

    #[test]
    fn privileged_argv_table_and_family_validators_enforce_allowlists() {
        use super::{
            is_loopback_dns_redirect_target, is_nft_daddr_family_token, is_nft_family_token,
            is_owned_dns_redirect_table_token, is_owned_failclosed_table_token,
            is_owned_nat_table_token, is_wg_endpoint_token,
        };

        // Fail-closed (killswitch) tables are anchored to the rustynet_g prefix;
        // the NAT prefix is deliberately a different owner and must not match.
        assert!(is_owned_failclosed_table_token("rustynet_g5"));
        assert!(!is_owned_failclosed_table_token("rustynet_nat_g5"));
        assert!(!is_owned_failclosed_table_token("filter"));
        assert!(!is_owned_failclosed_table_token("rustynet_g5; x"));

        // NAT tables require the rustynet_nat_g prefix.
        assert!(is_owned_nat_table_token("rustynet_nat_g5"));
        assert!(!is_owned_nat_table_token("rustynet_g5"));

        // DNS-redirect tables require both the prefix and the _dns suffix.
        assert!(is_owned_dns_redirect_table_token("rustynet_g5_dns"));
        assert!(!is_owned_dns_redirect_table_token("rustynet_g5"));
        assert!(!is_owned_dns_redirect_table_token("other_dns"));

        // nft family allowlists (daddr excludes "inet").
        assert!(is_nft_family_token("inet"));
        assert!(is_nft_family_token("ip"));
        assert!(is_nft_family_token("ip6"));
        assert!(!is_nft_family_token("arp"));
        assert!(!is_nft_family_token("IP"));
        assert!(!is_nft_family_token(""));
        assert!(is_nft_daddr_family_token("ip"));
        assert!(is_nft_daddr_family_token("ip6"));
        assert!(!is_nft_daddr_family_token("inet"));

        // Loopback DNS-redirect target: ":<nonzero u16>".
        assert!(is_loopback_dns_redirect_target(":53535"));
        assert!(!is_loopback_dns_redirect_target(":0"));
        assert!(!is_loopback_dns_redirect_target("53535"));
        assert!(!is_loopback_dns_redirect_target(":99999"));

        // WireGuard endpoints: non-empty host + in-range port.
        assert!(is_wg_endpoint_token("1.2.3.4:51820"));
        assert!(is_wg_endpoint_token("[fd00::1]:51820"));
        assert!(!is_wg_endpoint_token("nocolon"));
        assert!(!is_wg_endpoint_token(":51820"));
        assert!(!is_wg_endpoint_token("host:notaport"));
        assert!(!is_wg_endpoint_token("host:70000"));
    }

    #[test]
    fn privileged_argv_ip_and_chain_validators_enforce_allowlists() {
        use super::{
            is_allowed_ips_token, is_cidr_for_nft_family, is_exact_ip_for_nft_family,
            is_nft_chain_token,
        };

        // Allowed-IPs list: non-empty, and every comma-separated part is a CIDR.
        assert!(is_allowed_ips_token("10.0.0.0/8"));
        assert!(is_allowed_ips_token("10.0.0.0/8,fd00::/64"));
        assert!(!is_allowed_ips_token(""));
        assert!(!is_allowed_ips_token("10.0.0.0/8,notacidr"));
        assert!(!is_allowed_ips_token("10.0.0.0/8,")); // trailing empty part

        // Exact IP must match the declared nft family.
        assert!(is_exact_ip_for_nft_family("10.0.0.1", "ip"));
        assert!(is_exact_ip_for_nft_family("fd00::1", "ip6"));
        assert!(!is_exact_ip_for_nft_family("10.0.0.1", "ip6"));
        assert!(!is_exact_ip_for_nft_family("fd00::1", "ip"));
        assert!(!is_exact_ip_for_nft_family("10.0.0.1", "inet"));
        assert!(!is_exact_ip_for_nft_family("notanip", "ip"));

        // CIDR must match the family and stay within the prefix range.
        assert!(is_cidr_for_nft_family("10.0.0.0/8", "ip"));
        assert!(is_cidr_for_nft_family("fd00::/64", "ip6"));
        assert!(!is_cidr_for_nft_family("10.0.0.0/8", "ip6"));
        assert!(!is_cidr_for_nft_family("fd00::/64", "ip"));
        assert!(!is_cidr_for_nft_family("10.0.0.0/33", "ip"));

        // nft chain names are an exact allowlist.
        for chain in [
            "killswitch",
            "forward",
            "input",
            "output",
            "prerouting",
            "postrouting",
        ] {
            assert!(is_nft_chain_token(chain), "{chain} should be allowed");
        }
        assert!(!is_nft_chain_token("INPUT"));
        assert!(!is_nft_chain_token("evil"));
        assert!(!is_nft_chain_token(""));
    }

    #[test]
    fn peer_uid_reports_connected_socket_owner_uid() {
        // RN-17 gate primitive: the client re-checks `peer_uid(&stream) == Some(0)`
        // on the *connected* fd to reject a swapped, non-root socket. Verify the
        // primitive reports this process's own uid for a locally-created pair, so
        // a non-root server is correctly identified (and would be rejected).
        let (a, _b) = UnixStream::pair().expect("socket pair");
        let me = nix::unistd::getuid().as_raw();
        assert_eq!(peer_uid(&a), Some(me));
    }

    #[test]
    fn dns_redirect_commands_from_linux_dns_protect_are_all_permitted() {
        // The privileged helper must permit EXACTLY the nft commands the daemon
        // builds for the protected-mode DNS redirect (and the teardown).
        let table = crate::linux_dns_protect::dns_redirect_table_name(1);
        for argv in crate::linux_dns_protect::dns_redirect_nft_apply_argvs(&table, 53535) {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            assert!(
                super::validate_nft_args(&refs).is_ok(),
                "helper must permit DNS-redirect apply command: {refs:?}"
            );
        }
        let teardown = crate::linux_dns_protect::dns_redirect_nft_teardown_argv(&table);
        let refs: Vec<&str> = teardown.iter().map(String::as_str).collect();
        assert!(
            super::validate_nft_args(&refs).is_ok(),
            "helper must permit DNS-redirect teardown: {refs:?}"
        );
    }

    // ---- dns-failclosed-file builtin: privileged-boundary negative tests ----

    #[test]
    fn dns_failclosed_file_builtin_permits_exactly_the_reviewed_selectors() {
        for selector in crate::linux_dns_protect::DNS_FAILCLOSED_FILE_SELECTORS {
            assert!(
                validate_request(PrivilegedCommandProgram::DnsFailclosedFile, &[selector]).is_ok(),
                "helper must permit reviewed selector {selector:?}"
            );
        }
    }

    #[test]
    fn dns_failclosed_file_builtin_rejects_every_non_selector_argument() {
        // The selector is the entire attack surface: no path, no content, no
        // traversal, no shell metacharacters, no second argument may pass.
        for bad in [
            "",
            "resolv-conf",
            "resolv-conf-apply ",
            " resolv-conf-apply",
            "RESOLV-CONF-APPLY",
            "/etc/resolv.conf",
            "/etc/shadow",
            "../../etc/passwd",
            "resolv-conf-apply\n",
            "resolv-conf-apply;rm -rf /",
            "nameserver 8.8.8.8",
            "dns-failclosed-file",
        ] {
            assert!(
                validate_request(PrivilegedCommandProgram::DnsFailclosedFile, &[bad]).is_err(),
                "helper must reject non-selector argument {bad:?}"
            );
        }
    }

    #[test]
    fn dns_failclosed_file_builtin_requires_exactly_one_argument() {
        // Zero args (empty) is caught by the generic arity guard; two args and a
        // second-path smuggling attempt must both be rejected.
        assert!(
            validate_request(PrivilegedCommandProgram::DnsFailclosedFile, &[]).is_err(),
            "no argument must be rejected"
        );
        assert!(
            validate_request(
                PrivilegedCommandProgram::DnsFailclosedFile,
                &["resolv-conf-apply", "resolv-conf-restore"],
            )
            .is_err(),
            "two selectors must be rejected"
        );
        assert!(
            validate_request(
                PrivilegedCommandProgram::DnsFailclosedFile,
                &["resolv-conf-apply", "/etc/passwd"],
            )
            .is_err(),
            "a smuggled path as a second argument must be rejected"
        );
    }

    #[test]
    fn dns_failclosed_file_builtin_never_resolves_an_external_binary() {
        // The builtin must never reach the exec path; resolve_binary must fail
        // closed and is_builtin must classify it as in-process.
        assert!(PrivilegedCommandProgram::DnsFailclosedFile.is_builtin());
        let err = PrivilegedCommandProgram::DnsFailclosedFile
            .resolve_binary()
            .expect_err("builtin must have no external binary");
        assert!(err.contains("builtin"), "{err}");
    }

    #[test]
    fn dns_failclosed_file_program_token_round_trips() {
        let program = PrivilegedCommandProgram::DnsFailclosedFile;
        assert_eq!(
            program.as_str(),
            crate::linux_dns_protect::DNS_FAILCLOSED_FILE_PROGRAM
        );
        assert_eq!(
            PrivilegedCommandProgram::parse(program.as_str()),
            Some(program)
        );
    }

    #[test]
    fn handle_request_rejects_bad_selector_before_any_side_effect() {
        // A bad selector is rejected at validation — it never reaches the
        // in-process executor, so no file is ever touched.
        let response = handle_request(HelperRequest {
            program: crate::linux_dns_protect::DNS_FAILCLOSED_FILE_PROGRAM.to_owned(),
            args: vec!["/etc/resolv.conf".to_owned()],
        });
        assert!(!response.ok, "bad selector must fail");
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("dns-failclosed-file argument schema"),
            "must be the validation rejection, not an executor/exec error: {:?}",
            response.error
        );
    }

    #[test]
    fn handle_request_dispatches_valid_selector_to_in_process_executor() {
        // `resolv-conf-restore` with no backup present is a no-op, so this is
        // side-effect-free everywhere. The point is that a VALID selector is
        // dispatched to the builtin executor rather than rejected at validation
        // or sent down the binary-exec path.
        let response = handle_request(HelperRequest {
            program: crate::linux_dns_protect::DNS_FAILCLOSED_FILE_PROGRAM.to_owned(),
            args: vec!["resolv-conf-restore".to_owned()],
        });
        let error = response.error.clone().unwrap_or_default();
        assert!(
            !error.contains("argument schema"),
            "valid selector must pass validation and dispatch: {error:?}"
        );
        assert!(
            !error.contains("binary") && !error.contains("no supported binary path"),
            "builtin must never attempt to exec an external binary: {error:?}"
        );
    }

    // ---- linux-firewalld-zone builtin: privileged-boundary negative tests ----
    //
    // QH-46: the D-Bus executor itself (`execute_linux_firewalld_zone`) is
    // exercised only in the live lab — these pin the D-Bus-free boundary
    // layers: the argv grammar the helper enforces, the builtin classification,
    // and the binary-resolution refusal.

    #[test]
    fn linux_firewalld_zone_builtin_permits_exactly_the_two_token_grammar() {
        for op in ["query", "bind", "unbind"] {
            let op_token = format!("op={op}");
            assert!(
                validate_request(
                    PrivilegedCommandProgram::LinuxFirewalldZone,
                    &[op_token.as_str(), "interface=rustynet0"],
                )
                .is_ok(),
                "helper must permit the reviewed grammar for op {op:?}"
            );
        }
    }

    #[test]
    fn linux_firewalld_zone_builtin_rejects_zone_and_malformed_tokens() {
        // The ZONE is deliberately unrepresentable in this grammar — it is
        // always resolved server-side to the effective default zone. A caller
        // that could name a zone could name `trusted`, which would disable
        // firewalld's inbound filtering on the tunnel entirely (the exact
        // decision QH-46 documents rejecting). Every argv below must be
        // refused at validation.
        for bad in [
            &["op=bind", "interface=rustynet0", "zone=trusted"][..],
            &["op=bind", "interface=rustynet0", "zone=public"][..],
            &["op=bind", "interface=lo"][..],
            &["op=bind", "interface=../etc"][..],
            &["op=bind", "interface="][..],
            &["op=bind"][..],
            &["interface=rustynet0"][..],
            &["op=BIND", "interface=rustynet0"][..],
            &["op=detach", "interface=rustynet0"][..],
            &["op=bind", "op=bind", "interface=rustynet0"][..],
            &["op=bind", "interface=rustynet0", "interface=rustynet0"][..],
            &["op bind", "interface=rustynet0"][..],
        ] {
            assert!(
                validate_request(PrivilegedCommandProgram::LinuxFirewalldZone, bad).is_err(),
                "helper must reject firewalld zone argv {bad:?}"
            );
        }
    }

    #[test]
    fn linux_firewalld_zone_builtin_never_resolves_an_external_binary() {
        // The builtin must never reach the exec path; resolve_binary must fail
        // closed and is_builtin must classify it as in-process.
        assert!(PrivilegedCommandProgram::LinuxFirewalldZone.is_builtin());
        let err = PrivilegedCommandProgram::LinuxFirewalldZone
            .resolve_binary()
            .expect_err("builtin must have no external binary");
        assert!(err.contains("builtin"), "{err}");
    }

    #[test]
    fn linux_firewalld_zone_program_token_round_trips() {
        let program = PrivilegedCommandProgram::LinuxFirewalldZone;
        assert_eq!(
            program.as_str(),
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        assert_eq!(
            PrivilegedCommandProgram::parse(program.as_str()),
            Some(program)
        );
    }

    #[test]
    fn handle_request_rejects_zone_token_before_any_side_effect() {
        // A zone-bearing argv is rejected at validation — it never reaches the
        // in-process executor, so no D-Bus call is ever attempted.
        let response = handle_request(HelperRequest {
            program: crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM.to_owned(),
            args: vec![
                "op=bind".to_owned(),
                "interface=rustynet0".to_owned(),
                "zone=trusted".to_owned(),
            ],
        });
        assert!(!response.ok, "zone-bearing argv must fail");
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("unknown firewalld zone token"),
            "must be the grammar rejection, not an executor/D-Bus error: {:?}",
            response.error
        );
    }

    #[test]
    fn dns_redirect_validation_is_tightly_scoped() {
        use super::validate_nft_args;
        // nat/output chain permitted ONLY on a *_dns table — never the
        // filter-drop killswitch table (a redirect must not be slippable into
        // default-deny).
        assert!(
            validate_nft_args(&[
                "add",
                "chain",
                "inet",
                "rustynet_g1",
                "dns_redirect",
                "{",
                "type",
                "nat",
                "hook",
                "output",
                "priority",
                "dstnat",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ])
            .is_err(),
            "nat chain on the killswitch table must be rejected"
        );
        // redirect rule on a non-_dns table -> rejected.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "dns_redirect",
                "meta",
                "l4proto",
                "udp",
                "ip",
                "daddr",
                "127.0.0.1",
                "udp",
                "dport",
                "53",
                "redirect",
                "to",
                ":53535",
            ])
            .is_err(),
            "redirect on a non-_dns table must be rejected"
        );
        // off-loopback destination -> rejected (can't capture arbitrary DNS).
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g1_dns",
                "dns_redirect",
                "meta",
                "l4proto",
                "udp",
                "ip",
                "daddr",
                "8.8.8.8",
                "udp",
                "dport",
                "53",
                "redirect",
                "to",
                ":53535",
            ])
            .is_err(),
            "off-loopback daddr must be rejected"
        );
        // non-DNS destination port -> rejected.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g1_dns",
                "dns_redirect",
                "meta",
                "l4proto",
                "udp",
                "ip",
                "daddr",
                "127.0.0.1",
                "udp",
                "dport",
                "80",
                "redirect",
                "to",
                ":53535",
            ])
            .is_err(),
            "non-53 dport must be rejected"
        );
        // redirect target carrying an address (not a local socket) -> rejected.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g1_dns",
                "dns_redirect",
                "meta",
                "l4proto",
                "udp",
                "ip",
                "daddr",
                "127.0.0.1",
                "udp",
                "dport",
                "53",
                "redirect",
                "to",
                "1.2.3.4:53",
            ])
            .is_err(),
            "address-bearing redirect target must be rejected"
        );
        // l4proto / dport protocol mismatch -> rejected.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g1_dns",
                "dns_redirect",
                "meta",
                "l4proto",
                "udp",
                "ip",
                "daddr",
                "127.0.0.1",
                "tcp",
                "dport",
                "53",
                "redirect",
                "to",
                ":53535",
            ])
            .is_err(),
            "proto mismatch must be rejected"
        );
        // Regression: the killswitch filter-drop chain still validates.
        assert!(
            validate_nft_args(&[
                "add",
                "chain",
                "inet",
                "rustynet_g1",
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
            ])
            .is_ok(),
            "existing killswitch chain must still validate"
        );
    }

    #[test]
    fn blind_exit_nft_validation_is_tightly_scoped() {
        use super::validate_nft_args;
        // The blind_exit forward-chain flush is permitted (it keeps policy
        // drop while clearing the regular-exit unrestricted allow)...
        assert!(
            validate_nft_args(&["flush", "chain", "inet", "rustynet_g0", "forward"]).is_ok(),
            "blind_exit forward-chain flush must validate"
        );
        // ...but flushing the killswitch chain (or any non-forward chain) is
        // rejected so the default-deny posture can never be cleared this way.
        assert!(
            validate_nft_args(&["flush", "chain", "inet", "rustynet_g0", "killswitch"]).is_err(),
            "flushing the killswitch chain must be rejected"
        );
        // A flush on a non-owned table is rejected.
        assert!(
            validate_nft_args(&["flush", "chain", "inet", "evil_table", "forward"]).is_err(),
            "flush on a non-owned table must be rejected"
        );
        // The mesh-scoped final-hop forward allow validates for IPv4 + IPv6
        // mesh CIDRs.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g0",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "ip",
                "saddr",
                "100.64.0.0/10",
                "accept",
            ])
            .is_ok(),
            "IPv4 mesh-scoped forward allow must validate"
        );
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g0",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "ip6",
                "saddr",
                "fd7a::/48",
                "accept",
            ])
            .is_ok(),
            "IPv6 mesh-scoped forward allow must validate"
        );
        // Family/CIDR disagreement is rejected (no `ip saddr <v6>` slippage).
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "rustynet_g0",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "ip",
                "saddr",
                "fd7a::/48",
                "accept",
            ])
            .is_err(),
            "family/CIDR mismatch must be rejected"
        );
        // A non-owned table is rejected.
        assert!(
            validate_nft_args(&[
                "add",
                "rule",
                "inet",
                "evil_table",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "ip",
                "saddr",
                "100.64.0.0/10",
                "accept",
            ])
            .is_err(),
            "mesh-scoped forward allow on a non-owned table must be rejected"
        );
    }

    fn helper_request_frame_bytes(payload: &[u8], version: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(10 + payload.len());
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(version);
        frame.push(HELPER_FRAME_TYPE_REQUEST);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn write_frame_and_close(stream: &mut UnixStream, frame: &[u8]) {
        stream
            .write_all(frame)
            .expect("frame should be written successfully");
        stream
            .shutdown(Shutdown::Write)
            .expect("frame writer should shut down cleanly");
    }

    #[test]
    fn privileged_program_parser_rejects_unknown() {
        assert!(PrivilegedCommandProgram::parse("nft").is_some());
        assert!(PrivilegedCommandProgram::parse("not-real").is_none());
    }

    #[test]
    fn safe_token_rejects_unsafe_characters() {
        assert!(is_safe_token("established,related"));
        assert!(!is_safe_token("!="));
        assert!(!is_safe_token("$(id)"));
        assert!(!is_safe_token("a|b"));
        assert!(!is_safe_token("contains space"));
        assert!(is_nft_token("!="));
        assert!(is_nft_token("{"));
    }

    #[test]
    fn validate_request_rejects_invalid_nft_tokens() {
        let err = validate_request(
            PrivilegedCommandProgram::Nft,
            &["list", "table", "inet", "$(id)"],
        )
        .expect_err("unsafe token should be rejected");
        assert!(err.contains("unsupported nft argument schema"));
    }

    #[test]
    fn validate_request_accepts_known_ip_schema() {
        validate_request(
            PrivilegedCommandProgram::Ip,
            &[
                "route",
                "replace",
                "192.0.2.1/32",
                "dev",
                "rustynet0",
                "table",
                "51820",
            ],
        )
        .expect("known ip schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_ipv6_route_flush_table_schema() {
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["-6", "route", "flush", "table", "51820"],
        )
        .expect("ipv6 route flush schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_phase1_route_truth_probe_schemas() {
        validate_request(PrivilegedCommandProgram::Ip, &["rule", "show"])
            .expect("ip rule show schema should be accepted");
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["-4", "route", "show", "table", "51820"],
        )
        .expect("ip -4 route show table 51820 schema should be accepted");
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["-4", "route", "get", "1.1.1.1"],
        )
        .expect("ip -4 route get schema should be accepted");
    }

    // Mirrors validate_request_accepts_phase1_route_truth_probe_schemas' -4
    // case: assert_expected_bypass_routes' RouteTableFamily::V6 path (used
    // whenever a peer endpoint is IPv6) sends this exact argv, so it must be
    // allowlisted symmetrically with -4, not just the -6 replace/flush/get
    // variants already covered above.
    #[test]
    fn validate_request_accepts_ipv6_route_show_table_schema() {
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["-6", "route", "show", "table", "51820"],
        )
        .expect("ip -6 route show table 51820 schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_linux_userspace_shared_tuntap_schema() {
        validate_request(
            PrivilegedCommandProgram::Ip,
            &[
                "tuntap",
                "add",
                "dev",
                "rustynet0",
                "mode",
                "tun",
                "user",
                "1001",
                "group",
                "1001",
            ],
        )
        .expect("tuntap schema should be accepted");
    }

    #[test]
    fn validate_request_rejects_unknown_ip_schema() {
        let err = validate_request(
            PrivilegedCommandProgram::Ip,
            &["route", "replace", "192.0.2.1/32", "via", "198.51.100.1"],
        )
        .expect_err("unknown ip schema should be rejected");
        assert!(err.contains("unsupported ip argument schema"));
    }

    #[test]
    fn validate_request_rejects_unknown_wg_schema() {
        let err = validate_request(
            PrivilegedCommandProgram::Wg,
            &["set", "rustynet0", "fwmark", "51820"],
        )
        .expect_err("unknown wg schema should be rejected");
        assert!(err.contains("unsupported wg argument schema"));
    }

    #[test]
    fn validate_request_accepts_latest_handshakes_schema() {
        validate_request(
            PrivilegedCommandProgram::Wg,
            &["show", "rustynet0", "latest-handshakes"],
        )
        .expect("wg latest-handshakes schema should be accepted");
    }

    /// The exact argv `configure_peer` builds once
    /// `PeerConfig::persistent_keepalive_secs` is `Some` (FIS-0015).
    fn wg_keepalive_args(keepalive_secs: &'static str) -> [&'static str; 10] {
        [
            "set",
            "rustynet0",
            "peer",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            "endpoint",
            "198.51.100.7:51820",
            "allowed-ips",
            "100.64.0.7/32",
            "persistent-keepalive",
            keepalive_secs,
        ]
    }

    #[test]
    fn validate_request_accepts_persistent_keepalive_schema() {
        for keepalive_secs in ["25", "0", "65535"] {
            validate_request(
                PrivilegedCommandProgram::Wg,
                &wg_keepalive_args(keepalive_secs),
            )
            .unwrap_or_else(|err| panic!("keepalive {keepalive_secs} should be accepted: {err}"));
        }
    }

    #[test]
    fn validate_request_rejects_out_of_schema_persistent_keepalive_value() {
        // Widening the allowlist must not weaken the token guard: anything that
        // is not a canonical decimal in wg's `0..=65535` domain stays denied,
        // including the sign-prefixed form Rust's integer parser accepts and the
        // shell/path metacharacters the boundary exists to keep out.
        for keepalive_secs in [
            "65536",      // above u16
            "-1",         // negative
            "+21",        // parses as 21, but is not canonical
            "21s",        // unit suffix
            "twenty-one", // non-numeric
            "2 1",        // embedded whitespace
            "21; rm -rf /",
            "$(id)",
            "../../etc/passwd",
        ] {
            let err = validate_request(
                PrivilegedCommandProgram::Wg,
                &wg_keepalive_args(keepalive_secs),
            )
            .expect_err("out-of-schema keepalive value should be rejected");
            assert!(
                err.contains("unsupported wg argument schema"),
                "keepalive {keepalive_secs:?} rejected with unexpected error: {err}"
            );
        }
    }

    #[test]
    fn validate_request_rejects_empty_persistent_keepalive_value() {
        // An empty interval is denied one layer earlier than the schema arm, by
        // the generic empty-argument guard, so it carries that message instead.
        // Pinned separately rather than folded into the schema cases above so a
        // regression that moved the empty token past the hygiene check and into
        // the token guard would still have to be a deliberate change.
        let err = validate_request(PrivilegedCommandProgram::Wg, &wg_keepalive_args(""))
            .expect_err("empty keepalive value should be rejected");
        assert!(
            err.contains("empty argument"),
            "empty keepalive rejected with unexpected error: {err}"
        );
    }

    #[test]
    fn validate_request_rejects_unknown_trailing_token_after_allowed_ips() {
        // The keepalive arm is exact, not a prefix match: an unreviewed tail
        // attached to the same peer-configure shape stays default-denied.
        let err = validate_request(
            PrivilegedCommandProgram::Wg,
            &[
                "set",
                "rustynet0",
                "peer",
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                "endpoint",
                "198.51.100.7:51820",
                "allowed-ips",
                "100.64.0.7/32",
                "preshared-key",
                "/etc/rustynet/psk",
            ],
        )
        .expect_err("unreviewed trailing wg tokens should be rejected");
        assert!(err.contains("unsupported wg argument schema"));
    }

    /// Drives the REAL command backend through the REAL allowlist.
    ///
    /// The defect this pins was a coupling failure, not a logic error in either
    /// half: the backend appended `persistent-keepalive <n>` while the allowlist
    /// had no arm for it, and each side's own tests passed. Only a test that
    /// runs one against the other can catch that, so this runner validates every
    /// argv the backend emits instead of recording it.
    use rustynet_backend_api::BackendError;
    use rustynet_backend_wireguard::{
        LinuxWireguardBackend, WireguardCommandOutput, WireguardCommandRunner,
    };

    /// Rejections are recorded through a shared handle because the backend owns
    /// its runner and exposes no accessor.
    type RejectedArgv = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<String>, String)>>>;

    #[derive(Default)]
    struct AllowlistValidatingRunner {
        rejected: RejectedArgv,
    }

    impl WireguardCommandRunner for AllowlistValidatingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let _ = self.run_capture(program, args)?;
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            // Mirrors `PrivilegedHelperWireguardRunner`'s program mapping and
            // its validate-before-socket ordering, minus the socket.
            let helper_program = match program {
                "ip" => PrivilegedCommandProgram::Ip,
                "wg" => PrivilegedCommandProgram::Wg,
                "ifconfig" => PrivilegedCommandProgram::Ifconfig,
                "route" => PrivilegedCommandProgram::Route,
                "wireguard-go" => PrivilegedCommandProgram::WireguardGo,
                "kill" => PrivilegedCommandProgram::Kill,
                other => {
                    return Err(BackendError::invalid_input(format!(
                        "unexpected program {other}"
                    )));
                }
            };
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            if let Err(err) = validate_request(helper_program, &arg_refs) {
                self.rejected
                    .lock()
                    .expect("rejection log should not be poisoned")
                    .push((program.to_owned(), args.to_vec(), err.clone()));
                return Err(BackendError::internal(err));
            }
            Ok(WireguardCommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn allowlist_accepts_every_argv_the_linux_backend_emits_with_keepalive_enabled() {
        use rustynet_backend_api::{
            NodeId, PeerConfig, RuntimeContext, SocketEndpoint, TunnelBackend,
        };

        let rejected: RejectedArgv = RejectedArgv::default();
        let mut backend = LinuxWireguardBackend::new(
            AllowlistValidatingRunner {
                rejected: std::sync::Arc::clone(&rejected),
            },
            "rustynet0",
            "/etc/rustynet/wg.key",
            51820,
        )
        .expect("backend should construct");
        backend
            .start(RuntimeContext {
                local_node: NodeId::new("local-node").expect("valid node id"),
                interface_name: "rustynet0".to_owned(),
                mesh_cidr: "100.64.0.1/32".to_owned(),
                local_cidr: "100.64.0.1/32".to_owned(),
            })
            .expect("start argv should be allowlisted");

        let node_id = NodeId::new("peer-a").expect("valid node id");
        let endpoint = SocketEndpoint {
            addr: "203.0.113.10".parse().expect("valid ip"),
            port: 51820,
        };
        // FIS-0015 switched ON: this is the case that fails without the
        // persistent-keepalive arm.
        backend
            .configure_peer(PeerConfig {
                node_id: node_id.clone(),
                endpoint,
                public_key: [7; 32],
                allowed_ips: vec!["100.64.1.0/24".to_owned()],
                persistent_keepalive_secs: Some(25),
            })
            .expect("keepalive-enabled peer configure argv should be allowlisted");

        // Traversal promoting the peer to a direct address — the endpoint-only
        // shape, which carries no `allowed-ips` tail.
        backend
            .update_peer_endpoint(
                &node_id,
                SocketEndpoint {
                    addr: "198.51.100.7".parse().expect("valid ip"),
                    port: 51820,
                },
            )
            .expect("endpoint-only update argv should be allowlisted");

        backend
            .remove_peer(&node_id)
            .expect("peer removal argv should be allowlisted");

        let rejected = rejected
            .lock()
            .expect("rejection log should not be poisoned");
        assert!(
            rejected.is_empty(),
            "backend emitted argv the allowlist denies: {rejected:?}"
        );
    }

    #[test]
    fn validate_request_accepts_endpoint_only_peer_update_schema() {
        // `update_peer_endpoint`'s shape, emitted when NAT traversal promotes a
        // peer to a direct address.
        validate_request(
            PrivilegedCommandProgram::Wg,
            &[
                "set",
                "rustynet0",
                "peer",
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                "endpoint",
                "198.51.100.7:51820",
            ],
        )
        .expect("endpoint-only peer update schema should be accepted");
    }

    #[test]
    fn validate_request_rejects_endpoint_only_peer_update_with_bad_endpoint() {
        for endpoint in ["198.51.100.7", "198.51.100.7:0", "198.51.100.7:51820; id"] {
            let err = validate_request(
                PrivilegedCommandProgram::Wg,
                &[
                    "set",
                    "rustynet0",
                    "peer",
                    "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                    "endpoint",
                    endpoint,
                ],
            )
            .expect_err("malformed endpoint should be rejected");
            assert!(
                err.contains("unsupported wg argument schema"),
                "endpoint {endpoint:?} rejected with unexpected error: {err}"
            );
        }
    }

    #[test]
    fn validate_request_accepts_known_nft_list_table_schema() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &["list", "table", "inet", "rustynet_g1"],
        )
        .expect("known nft list table schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_management_ssh_fail_closed_rule_schema() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "ip",
                "daddr",
                "192.168.18.0/24",
                "tcp",
                "dport",
                "22",
                "accept",
            ],
        )
        .expect("management ssh fail-closed rule schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_traversal_bootstrap_allow_rule_schema() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "oifname",
                "enp0s1",
                "ip",
                "daddr",
                "203.0.113.10",
                "udp",
                "dport",
                "3478",
                "accept",
                "comment",
                "rustynet_traversal_bootstrap",
            ],
        )
        .expect("traversal bootstrap allow rule schema should be accepted");
    }

    #[test]
    fn validate_request_accepts_wireguard_listen_port_egress_allow_rule() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "oifname",
                "enp0s1",
                "udp",
                "dport",
                "51820",
                "accept",
            ],
        )
        .expect("wireguard listen port egress allow rule schema should be accepted");
    }

    #[test]
    fn validate_request_rejects_wireguard_listen_port_rule_with_non_port() {
        let err = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "oifname",
                "enp0s1",
                "udp",
                "dport",
                "notaport",
                "accept",
            ],
        )
        .expect_err("non-numeric port in wg listen rule must be rejected");
        assert!(err.contains("unsupported nft add rule argument schema"));
    }

    /// The nft refusal must NAME the rejected argv, and `wg` must NOT.
    ///
    /// Both halves are the point. Without the argv, a refusal says only that the
    /// privileged boundary held — which left a real `entry`-role rule shape
    /// diagnosable only by reading daemon source and guessing (QH-45). But `wg`
    /// argv can carry a private key, so the same disclosure there would be a
    /// secrets leak out of the most sensitive surface in the daemon. The
    /// The entry/relay hairpin forward rule is accepted, and near-misses are not.
    ///
    /// The accepted shape is the exact argv the helper refused in QH-45, which
    /// stopped fedora's daemon and made live_two_hop_validation unrunnable. It
    /// grants no authority the sibling arm did not already grant — `counter` is a
    /// pure statement affecting neither match nor verdict — so the negative cases
    /// below are what prove the arm is narrow rather than a loosening: an
    /// unowned table, a malformed interface name, and `counter` without a verdict
    /// The NAT half of the same hairpin, and its near-misses.
    ///
    /// Allowlisting only the `forward` counter arm did not fix QH-45: both
    /// emitters are gated by the same flag, so the run merely died one step later
    /// in NAT apply instead of firewall apply. A fix that moves an error string
    /// is not a fix, and this test is what would have caught that.
    #[test]
    fn postrouting_counter_masquerade_is_allowed_only_as_a_hairpin() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                "rustynet_nat_g2",
                "postrouting",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
                "masquerade",
            ],
        )
        .expect("the entry/relay NAT hairpin must be accepted");

        let cross_iface = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                "rustynet_nat_g2",
                "postrouting",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "counter",
                "masquerade",
            ],
        )
        .expect_err("this arm is hairpin-only; differing interfaces must not match it");
        assert!(cross_iface.contains("unsupported nft add rule argument schema"));

        let unowned = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                "not_ours",
                "postrouting",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
                "masquerade",
            ],
        )
        .expect_err("a table we do not own must still be refused");
        assert!(unowned.contains("unsupported nft add rule argument schema"));

        let wildcard = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                "rustynet_nat_g2",
                "postrouting",
                "iifname",
                "*",
                "oifname",
                "*",
                "counter",
                "masquerade",
            ],
        )
        .expect_err("an nft wildcard interface must never be accepted");
        assert!(wildcard.contains("unsupported nft add rule argument schema"));
    }

    /// must all still be refused.
    #[test]
    fn forward_counter_accept_is_allowed_only_in_its_exact_narrow_shape() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g2",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
                "accept",
            ],
        )
        .expect("the entry/relay hairpin forward rule must be accepted");

        let unowned = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "not_ours",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
                "accept",
            ],
        )
        .expect_err("a table we do not own must still be refused");
        assert!(unowned.contains("unsupported nft add rule argument schema"));

        let bad_iface = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g2",
                "forward",
                "iifname",
                "rustynet0; rm -rf /",
                "oifname",
                "rustynet0",
                "counter",
                "accept",
            ],
        )
        .expect_err("a malformed interface name must still be refused");
        assert!(bad_iface.contains("unsupported nft add rule argument schema"));

        let no_verdict = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g2",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
            ],
        )
        .expect_err("counter without a verdict must still be refused");
        assert!(no_verdict.contains("unsupported nft add rule argument schema"));

        let drop_swapped = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g2",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "rustynet0",
                "counter",
                "masquerade",
            ],
        )
        .expect_err("a different verdict must not ride in on this arm");
        assert!(drop_swapped.contains("unsupported nft add rule argument schema"));
    }

    /// asymmetry is deliberate and this test is what keeps it.
    #[test]
    fn nft_refusal_names_the_argv_and_wg_refusal_never_does() {
        let nft_err = validate_request(
            PrivilegedCommandProgram::Nft,
            &["add", "rule", "inet", "bogus_table", "some_chain"],
        )
        .expect_err("an unknown nft rule shape must be refused");
        assert!(
            nft_err.contains("bogus_table") && nft_err.contains("some_chain"),
            "the nft refusal must name what was rejected so it can be diagnosed; got: {nft_err}"
        );

        let secret = "SECRETKEYMATERIAL0000000000000000000000000000";
        let wg_err = validate_request(
            PrivilegedCommandProgram::Wg,
            &["set", "wg0", "private-key", secret],
        )
        .expect_err("an unknown wg shape must be refused");
        assert!(
            !wg_err.contains(secret),
            "a wg refusal must never echo its arguments; got: {wg_err}"
        );
    }

    #[test]
    fn validate_request_rejects_traversal_bootstrap_allow_rule_with_cidr() {
        let err = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "oifname",
                "enp0s1",
                "ip",
                "daddr",
                "203.0.113.0/24",
                "udp",
                "dport",
                "3478",
                "accept",
                "comment",
                "rustynet_traversal_bootstrap",
            ],
        )
        .expect_err("cidr traversal bootstrap rule schema should be rejected");
        assert!(err.contains("unsupported nft add rule argument schema"));
    }

    #[test]
    fn validate_request_rejects_unknown_nft_rule_schema() {
        let err = validate_request(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "meta",
                "mark",
                "0x1",
                "accept",
            ],
        )
        .expect_err("unknown nft rule schema should be rejected");
        assert!(err.contains("unsupported nft add rule argument schema"));
    }

    #[test]
    fn validate_request_rejects_too_many_arguments() {
        let args = vec!["x"; MAX_ARGS + 1];
        let err = validate_request(PrivilegedCommandProgram::Ip, args.as_slice())
            .expect_err("argument-count overflow must be rejected");
        assert!(err.contains("too many arguments"));
    }

    #[test]
    fn validate_request_rejects_argument_over_max_bytes() {
        let oversized = "a".repeat(MAX_ARG_BYTES + 1);
        let args = vec![oversized.as_str()];
        let err = validate_request(PrivilegedCommandProgram::Ip, args.as_slice())
            .expect_err("oversized argument must be rejected");
        assert!(err.contains("argument too long"));
    }

    #[test]
    fn fuzzgate_read_request_rejects_oversized_payload() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut frame = Vec::new();
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(HELPER_FRAME_VERSION);
        frame.push(HELPER_FRAME_TYPE_REQUEST);
        frame.extend_from_slice(&((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        let writer = std::thread::spawn(move || {
            write_frame_and_close(&mut client_stream, &frame);
        });

        let err = read_request(&mut server_stream)
            .expect_err("oversized privileged helper request must be rejected");
        writer.join().expect("writer thread should complete");
        assert!(err.contains("frame payload exceeds maximum size"));
    }

    #[test]
    fn validate_request_accepts_macos_endpoint_route_get_schema() {
        // Regression coverage for the live-lab-verified full-tunnel
        // blackhole: the macOS WireGuard backend probes `route -n get
        // -inet|-inet6 <endpoint>` to decide whether a peer underlay
        // endpoint needs a /32 bypass before the split-default halves are
        // installed. When the helper rejected this schema, the probe's
        // error arm classified every endpoint as on-link and no bypass was
        // ever installed.
        validate_request(
            PrivilegedCommandProgram::Route,
            &["-n", "get", "-inet", "192.168.64.4"],
        )
        .expect("ipv4 endpoint route get schema should be accepted");
        validate_request(
            PrivilegedCommandProgram::Route,
            &["-n", "get", "-inet6", "fd7a:115c:a1e0::1"],
        )
        .expect("ipv6 endpoint route get schema should be accepted");
    }

    #[test]
    fn validate_request_rejects_macos_endpoint_route_get_non_ip_target() {
        let err = validate_request(
            PrivilegedCommandProgram::Route,
            &["-n", "get", "-inet", "default;sudo"],
        )
        .expect_err("non-IP endpoint route get target must be rejected");
        assert!(err.contains("unsupported route argument schema"));
    }

    #[test]
    fn validate_request_accepts_the_bring_up_mtu_set_only_inside_the_audited_range() {
        // Regression coverage for the live-lab-verified enforce_baseline_runtime
        // failure: FIS-0027 Phase 2 (fef40bb) made the Linux WireGuard bring-up
        // run `ip link set mtu <SAFE_BRINGUP_TUNNEL_MTU> dev <iface>`, but the
        // schema was never added to validate_ip_args, so the helper rejected it
        // on every Linux host -> reconcile-failure cascade -> rustynet0 never
        // appeared -> the managed-DNS unit's 20s wait timed out.

        // The exact schema linux_command.rs sends must be accepted.
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["link", "set", "mtu", "1420", "dev", "rustynet0"],
        )
        .expect("the bring-up MTU-set schema linux_command sends must be accepted");

        // The bring-up value is now resolved per host (a NAT-traversed path can
        // ride a carrier with a smaller MTU than the 1500-byte underlay the
        // default assumes), so the entry is a bounded RANGE rather than an exact
        // literal. The bound is what keeps it a narrow capability grant instead
        // of a lazy `parse::<u16>().is_ok()`.

        // Above the ceiling must be REJECTED. The ceiling is the audited
        // default, so an override can only ever make the tunnel more
        // conservative -- never grant a larger MTU than before.
        for over in ["9999", "1421"] {
            let err = validate_request(
                PrivilegedCommandProgram::Ip,
                &["link", "set", "mtu", over, "dev", "rustynet0"],
            )
            .expect_err("an MTU above the audited bring-up ceiling must be rejected");
            assert!(err.contains("unsupported ip argument schema"));
        }

        // Below the floor must also be REJECTED, so a typo cannot cripple the
        // link to an unusable MTU.
        for under in ["576", "1199", "0"] {
            let err = validate_request(
                PrivilegedCommandProgram::Ip,
                &["link", "set", "mtu", under, "dev", "rustynet0"],
            )
            .expect_err("an MTU below the audited bring-up floor must be rejected");
            assert!(err.contains("unsupported ip argument schema"));
        }

        // A legitimate constrained-path value inside the range is accepted --
        // 1220 is what the measured 1280-byte cross-network path needs.
        validate_request(
            PrivilegedCommandProgram::Ip,
            &["link", "set", "mtu", "1220", "dev", "rustynet0"],
        )
        .expect("an in-range constrained-path MTU must be accepted");

        // Non-numeric junk must never reach `ip`.
        let err = validate_request(
            PrivilegedCommandProgram::Ip,
            &["link", "set", "mtu", "1420; rm -rf /", "dev", "rustynet0"],
        )
        .expect_err("a non-numeric MTU token must be rejected");
        assert!(err.contains("unsupported ip argument schema"));

        // A non-interface-name `dev` target must also be rejected.
        let err = validate_request(
            PrivilegedCommandProgram::Ip,
            &["link", "set", "mtu", "1420", "dev", "rustynet0;sudo"],
        )
        .expect_err("a non-interface-name dev target must be rejected");
        assert!(err.contains("unsupported ip argument schema"));
    }

    #[test]
    fn helper_frame_rejects_invalid_magic() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let payload = encode_helper_request(&HelperRequest {
            program: "ip".to_owned(),
            args: vec!["--version".to_owned()],
        })
        .expect("request payload should encode");
        let mut frame = helper_request_frame_bytes(&payload, HELPER_FRAME_VERSION);
        frame[..4].copy_from_slice(b"BAD!");
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream).expect_err("invalid magic must fail");
        assert!(err.contains("invalid frame magic"));
    }

    #[test]
    fn helper_frame_rejects_unknown_version() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let payload = encode_helper_request(&HelperRequest {
            program: "ip".to_owned(),
            args: vec!["--version".to_owned()],
        })
        .expect("request payload should encode");
        let frame = helper_request_frame_bytes(&payload, HELPER_FRAME_VERSION + 1);
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream).expect_err("unknown version must fail");
        assert!(err.contains("unsupported frame version"));
    }

    #[test]
    fn helper_frame_rejects_truncated_payload() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut frame = Vec::new();
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(HELPER_FRAME_VERSION);
        frame.push(HELPER_FRAME_TYPE_REQUEST);
        frame.extend_from_slice(&10u32.to_be_bytes());
        frame.extend_from_slice(b"short");
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream).expect_err("truncated payload must fail");
        assert!(err.contains("truncated frame payload"));
    }

    #[cfg(not(windows))]
    #[test]
    fn truncated_response_error_names_the_timeout_not_corruption() {
        // Regression pin for a live 2-core-guest failure: the daemon logged
        // `privileged helper response read failed: truncated frame header` in a
        // continuous loop, which reads as protocol corruption. It was the
        // helper's own I/O timeout elapsing mid-command; raising it from
        // 2000 ms to 10000 ms stopped it dead. On a length-prefixed IPC an EOF
        // mid-frame can only mean the peer went away.
        let annotated = super::annotate_helper_response_read_error(
            "privileged helper response read failed: truncated frame header".to_owned(),
        );
        assert!(
            annotated.contains("RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS"),
            "a truncated response must name the timeout knob: {annotated}"
        );
        assert!(
            annotated.contains("not protocol corruption"),
            "a truncated response must steer the reader away from transport damage: {annotated}"
        );

        // A non-truncation read failure must be left exactly as-is, so this
        // cannot misattribute an unrelated I/O fault to the timeout.
        let untouched = "privileged helper response read failed: read frame header failed: \
             Connection reset by peer"
            .to_owned();
        assert_eq!(
            super::annotate_helper_response_read_error(untouched.clone()),
            untouched,
            "only truncation carries the timeout hint"
        );
    }

    #[test]
    fn helper_frame_rejects_trailing_payload_bytes() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut payload = encode_helper_request(&HelperRequest {
            program: "ip".to_owned(),
            args: vec!["--version".to_owned()],
        })
        .expect("request payload should encode");
        payload.push(0xff);
        let frame = helper_request_frame_bytes(&payload, HELPER_FRAME_VERSION);
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream).expect_err("trailing bytes must fail");
        assert!(err.contains("trailing bytes after helper payload"));
    }

    #[test]
    fn helper_frame_round_trips_request_and_response() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("server read timeout should be set");
        server_stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("server write timeout should be set");
        client_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout should be set");
        client_stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("client write timeout should be set");

        let server = std::thread::spawn(move || {
            let request = read_request(&mut server_stream).expect("request should decode");
            assert_eq!(request.program, "ip");
            assert_eq!(request.args, vec!["--version".to_owned()]);
            write_response(
                &mut server_stream,
                HelperResponse::success(0, "ok".to_owned(), String::new()),
            )
            .expect("response should encode");
        });

        write_request_frame(
            &mut client_stream,
            &HelperRequest {
                program: "ip".to_owned(),
                args: vec!["--version".to_owned()],
            },
        )
        .expect("request should encode");
        let response = read_response_frame(&mut client_stream).expect("response should decode");
        assert!(response.ok);
        assert_eq!(response.status, Some(0));
        assert_eq!(response.stdout.as_deref(), Some("ok"));
        assert_eq!(response.stderr.as_deref(), Some(""));
        assert_eq!(response.error, None);

        server.join().expect("server thread should join cleanly");
    }

    #[test]
    fn fuzzgate_rejects_unknown_tokens_and_shell_metacharacters() {
        let unknown_program = handle_request(HelperRequest {
            program: "not-a-real-program".to_owned(),
            args: vec!["--version".to_owned()],
        });
        assert!(!unknown_program.ok);
        assert_eq!(unknown_program.status, None);
        assert!(unknown_program.error.is_some());
        assert!(
            unknown_program
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("unsupported privileged command program")
        );

        let shell_like_tokens = [
            "$(id)",
            "`id`",
            "a|b",
            "a;b",
            "a&&b",
            "a||b",
            "contains space",
            "$HOME",
            ">out",
            "<in",
        ];

        for token in shell_like_tokens {
            let ip_err = validate_request(
                PrivilegedCommandProgram::Ip,
                &["link", "set", "up", "dev", token],
            )
            .expect_err("ip schema should reject shell-like token");
            assert!(ip_err.contains("unsupported ip argument schema"));

            let wg_err = validate_request(
                PrivilegedCommandProgram::Wg,
                &["set", "rustynet0", "peer", token, "remove"],
            )
            .expect_err("wg schema should reject shell-like token");
            assert!(wg_err.contains("unsupported wg argument schema"));

            let pf_err = validate_request(
                PrivilegedCommandProgram::Pfctl,
                &["-a", token, "-s", "rules"],
            )
            .expect_err("pfctl schema should reject shell-like token");
            assert!(
                pf_err.contains("unsupported pfctl token")
                    || pf_err.contains("unsupported pfctl argument schema")
            );
        }
    }

    #[test]
    fn fuzzgate_malformed_inputs_never_panic() {
        let mut malformed_payloads = Vec::new();
        malformed_payloads.push(Vec::new());
        malformed_payloads.push(vec![0u8; 3]);
        malformed_payloads.push(helper_request_frame_bytes(
            b"\x00",
            HELPER_FRAME_VERSION + 1,
        ));
        malformed_payloads.push(helper_request_frame_bytes(b"\x00", HELPER_FRAME_VERSION));
        malformed_payloads.push({
            let mut frame = helper_request_frame_bytes(b"\x00", HELPER_FRAME_VERSION);
            frame[..4].copy_from_slice(b"BAD!");
            frame
        });
        malformed_payloads.push({
            let mut frame = Vec::new();
            frame.extend_from_slice(&HELPER_FRAME_MAGIC);
            frame.push(HELPER_FRAME_VERSION);
            frame.push(HELPER_FRAME_TYPE_REQUEST);
            frame.extend_from_slice(&10u32.to_be_bytes());
            frame.extend_from_slice(b"tiny");
            frame
        });
        malformed_payloads.push({
            let mut payload = encode_helper_request(&HelperRequest {
                program: "ip".to_owned(),
                args: vec!["link".to_owned()],
            })
            .expect("request payload should encode");
            payload.push(0x01);
            helper_request_frame_bytes(&payload, HELPER_FRAME_VERSION)
        });

        for payload in malformed_payloads {
            let (mut server_stream, mut client_stream) =
                UnixStream::pair().expect("unix stream pair should be created");
            server_stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout should be set");
            client_stream
                .write_all(&payload)
                .expect("malformed payload should be written");
            let _ = client_stream.shutdown(Shutdown::Write);

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_request(&mut server_stream)
            }));
            assert!(
                outcome.is_ok(),
                "read_request panicked on malformed payload"
            );
        }

        let malformed_requests = vec![
            HelperRequest {
                program: String::new(),
                args: vec![],
            },
            HelperRequest {
                program: "not-real".to_owned(),
                args: vec!["--version".to_owned()],
            },
            HelperRequest {
                program: "ip".to_owned(),
                args: vec![],
            },
            HelperRequest {
                program: "ip".to_owned(),
                args: vec![
                    "route".to_owned(),
                    "replace".to_owned(),
                    "0.0.0.0/0".to_owned(),
                    "via".to_owned(),
                    "203.0.113.1".to_owned(),
                ],
            },
            HelperRequest {
                program: "nft".to_owned(),
                args: vec![
                    "list".to_owned(),
                    "table".to_owned(),
                    "inet".to_owned(),
                    "$(id)".to_owned(),
                ],
            },
            HelperRequest {
                program: "kill".to_owned(),
                args: vec!["-TERM".to_owned(), "1".to_owned()],
            },
        ];

        for request in malformed_requests {
            let outcome = std::panic::catch_unwind(|| handle_request(request.clone()));
            assert!(
                outcome.is_ok(),
                "handle_request panicked for malformed input"
            );
            let response = outcome.expect("panic already asserted absent");
            assert!(!response.ok);
            assert!(response.error.is_some());
        }
    }

    #[test]
    fn privileged_subprocess_times_out_and_is_killed() {
        if !Path::new("/bin/sh").exists() {
            return;
        }
        let err = run_privileged_subprocess(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "sleep 1".to_owned()],
            Duration::from_millis(50),
        )
        .expect_err("sleeping subprocess should time out");
        assert!(err.contains("timed out after 50 ms"));
    }

    #[test]
    fn validate_privileged_program_binary_rejects_group_or_other_writable_binary() {
        let unique = format!(
            "rnh-bin-gw-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = PathBuf::from("/tmp").join(unique);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("test binary should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777))
            .expect("test binary mode should be set");

        let err = validate_privileged_program_binary(&path, "test")
            .expect_err("group/other writable binary must be rejected");
        assert!(err.contains("must not be group/other writable"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validate_privileged_program_binary_rejects_non_root_owned_binary() {
        if nix::unistd::Uid::current().is_root() {
            return;
        }

        let unique = format!(
            "rnh-bin-owner-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = PathBuf::from("/tmp").join(unique);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("test binary should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("test binary mode should be set");

        let err = validate_privileged_program_binary(&path, "test")
            .expect_err("non-root-owned binary must be rejected");
        assert!(err.contains("must be root-owned"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn privileged_helper_socket_validator_rejects_regular_file_path() {
        let unique = format!(
            "rnh-sock-regular-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = PathBuf::from("/tmp").join(unique);
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("helper.sock");
        std::fs::write(&socket, b"not-a-socket").expect("regular file should exist");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("regular file permissions should be owner-only");

        let err = validate_privileged_helper_socket_security(&socket)
            .expect_err("regular file must not validate as helper socket");
        assert!(err.contains("must be a Unix socket"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn privileged_helper_socket_validator_rejects_symlink_path() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "rnh-sock-link-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = PathBuf::from("/tmp").join(unique);
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("helper.sock.target");
        let symlink_path = dir.join("helper.sock.link");
        std::fs::write(&socket, b"not-a-socket").expect("target file should exist");
        symlink(&socket, &symlink_path).expect("symlink should be created");

        let err = validate_privileged_helper_socket_security(&symlink_path)
            .expect_err("symlink helper socket path must fail");
        assert!(err.contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn helper_frame_rejects_zero_length_payload() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut frame = Vec::new();
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(HELPER_FRAME_VERSION);
        frame.push(HELPER_FRAME_TYPE_REQUEST);
        frame.extend_from_slice(&0u32.to_be_bytes());
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream)
            .expect_err("zero-length privileged helper frame must be rejected");
        assert!(err.contains("frame payload must not be empty"));
    }

    #[test]
    fn helper_frame_rejects_unknown_frame_type_failclosed() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        // Build a well-formed payload but tag the frame as a RESPONSE so the
        // server-side request reader (which expects REQUEST) rejects it.
        let payload = encode_helper_request(&HelperRequest {
            program: "ip".to_owned(),
            args: vec!["--version".to_owned()],
        })
        .expect("request payload should encode");
        let mut frame = Vec::new();
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(HELPER_FRAME_VERSION);
        frame.push(HELPER_FRAME_TYPE_RESPONSE);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream)
            .expect_err("mismatched frame type must be rejected fail-closed");
        assert!(err.contains("unexpected frame type"));
    }

    #[test]
    fn helper_frame_rejects_unknown_arbitrary_frame_type() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut frame = Vec::new();
        frame.extend_from_slice(&HELPER_FRAME_MAGIC);
        frame.push(HELPER_FRAME_VERSION);
        frame.push(0xAB); // unknown discriminant
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.push(0x00);
        write_frame_and_close(&mut client_stream, &frame);

        let err = read_request(&mut server_stream)
            .expect_err("arbitrary frame discriminant must be rejected");
        assert!(err.contains("unexpected frame type"));
    }

    #[test]
    fn helper_request_decoder_rejects_non_utf8_program_field() {
        // Build a payload with a length-prefixed program field whose bytes
        // are not valid UTF-8. The decoder must reject this rather than
        // treating it as a string.
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&[0xFF, 0xFE]); // not valid utf-8
        payload.extend_from_slice(&0u16.to_be_bytes()); // 0 args
        let err =
            decode_helper_request(&payload).expect_err("non-utf-8 program field must be rejected");
        assert!(err.contains("not valid utf-8"));
    }

    #[test]
    fn helper_request_decoder_rejects_non_utf8_arg_field() {
        let mut payload = Vec::new();
        // program = "ip"
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(b"ip");
        // 1 arg
        payload.extend_from_slice(&1u16.to_be_bytes());
        // arg with invalid utf-8 continuation
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&[0x80, 0x80, 0x80]);
        let err =
            decode_helper_request(&payload).expect_err("non-utf-8 arg field must be rejected");
        assert!(err.contains("not valid utf-8"));
    }

    #[test]
    fn helper_request_decoder_handles_adversarial_bytes_without_panic() {
        let mut seed = 0x726e_6866_5f64_6563u64;
        for len in 0..=512usize {
            let mut payload = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                payload.push((seed >> 32) as u8);
            }
            let decoded = std::panic::catch_unwind(|| decode_helper_request(payload.as_slice()));
            let result = decoded.expect("decode_helper_request must not panic");
            if let Ok(request) = result {
                assert!(
                    request.program.len() <= MAX_PROGRAM_BYTES,
                    "decoded program exceeded max bytes"
                );
                assert!(
                    request.args.len() <= MAX_ARGS,
                    "decoded arg count exceeded max args"
                );
                for arg in request.args {
                    assert!(arg.len() <= MAX_ARG_BYTES, "decoded arg exceeded max bytes");
                }
            }
        }
    }

    #[test]
    fn validate_request_rejects_cidr_field_with_shell_metacharacters() {
        // Inject classic shell metacharacters into the CIDR slot of the most
        // common variable schema. The strict validator must reject every form
        // before the request can reach exec.
        let injection_attempts = [
            "; rm -rf /",
            "$(ls)",
            "`id`",
            "10.0.0.0/24; reboot",
            "10.0.0.0/24$(echo pwn)",
        ];
        for attempt in injection_attempts {
            let err = validate_request(
                PrivilegedCommandProgram::Ip,
                &["route", "replace", attempt, "dev", "rustynet0"],
            )
            .expect_err("shell-metachar CIDR must be rejected");
            assert!(err.contains("unsupported ip argument schema"));
        }
    }

    #[test]
    fn validate_request_rejects_interface_field_with_newline() {
        let err = validate_request(
            PrivilegedCommandProgram::Ip,
            &["link", "set", "up", "dev", "wg0\nrm -rf /"],
        )
        .expect_err("newline in interface name must be rejected");
        assert!(err.contains("unsupported ip argument schema"));

        // also via the wg endpoint variant
        let err = validate_request(
            PrivilegedCommandProgram::Wg,
            &["show", "wg0\nls", "latest-handshakes"],
        )
        .expect_err("newline in wg interface name must be rejected");
        assert!(err.contains("unsupported wg argument schema"));
    }

    #[test]
    fn validate_request_rejects_path_traversal_in_private_key_path() {
        // Direct token-level check: parent-directory traversal must not pass
        // is_path_token even though the dot character is otherwise allowed.
        assert!(!is_path_token("/etc/wg/../shadow"));
        assert!(!is_path_token("/etc/wg/.."));
        assert!(!is_path_token("/.."));
        assert!(is_path_token("/etc/wg/private.key"));
        // The valid case must still validate end-to-end.
        validate_request(
            PrivilegedCommandProgram::Wg,
            &[
                "set",
                "rustynet0",
                "private-key",
                "/etc/rustynet/private.key",
            ],
        )
        .expect("clean private-key path must validate");
        // And the traversal case must be rejected by the schema.
        let err = validate_request(
            PrivilegedCommandProgram::Wg,
            &[
                "set",
                "rustynet0",
                "private-key",
                "/etc/rustynet/../../etc/shadow",
            ],
        )
        .expect_err("private-key path traversal must be rejected");
        assert!(err.contains("unsupported wg argument schema"));
    }

    #[test]
    fn validate_request_rejects_path_traversal_in_pfctl_anchor_load() {
        let err = validate_request(
            PrivilegedCommandProgram::Pfctl,
            &[
                "-a",
                "com.apple/rustynet_g1",
                "-f",
                "/etc/rustynet/../../etc/shadow",
            ],
        )
        .expect_err("pfctl load-from path traversal must be rejected");
        assert!(err.contains("unsupported pfctl argument schema"));
    }

    #[test]
    fn validate_request_rejects_pfctl_boundary_rule_file_load() {
        // Audit major #5 boundary closure. The privileged boundary must NOT
        // accept a daemon-supplied pf rules file for ANY anchor — neither the
        // plain `-f` load nor the `-n -f` syntax check. A daemon compromised to
        // the helper's uid could otherwise author `pass out quick all` and have
        // the root helper load it into the killswitch anchor, defeating
        // default-deny egress. All rule loading now goes through the
        // `macos-pf-load` builtin, which re-renders the rule text in the helper.
        for argv in [
            [
                "-n",
                "-a",
                "com.rustynet/blind_exit",
                "-f",
                "/etc/rustynet/b.pf",
            ]
            .as_slice(),
            ["-a", "com.rustynet/blind_exit", "-f", "/etc/rustynet/b.pf"].as_slice(),
            ["-a", "com.apple/rustynet_g7", "-f", "/tmp/k.pf"].as_slice(),
            ["-n", "-a", "com.rustynet/nat", "-f", "/tmp/nat.pf"].as_slice(),
            ["-a", "com.rustynet/nat", "-f", "/tmp/nat.pf"].as_slice(),
        ] {
            let err = validate_request(PrivilegedCommandProgram::Pfctl, argv)
                .expect_err("pfctl -f rule-file load must be rejected at the boundary");
            assert!(
                err.contains("unsupported pfctl argument schema"),
                "got: {err}"
            );
        }

        // The replacement path — the macos-pf-load builtin carrying a validated
        // structured spec (no daemon-supplied path/anchor/rule-text) — IS
        // accepted at the boundary.
        let spec = crate::macos_pf_load_spec::MacosPfLoadSpec::ExitNat {
            config: crate::macos_exit_nat::MacosExitNatPfConfig::new(
                "en0",
                vec!["100.64.0.0/10".to_owned()],
            )
            .expect("exit nat config"),
        };
        let encoded = spec.encode();
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        validate_request(PrivilegedCommandProgram::MacosPfLoad, &refs)
            .expect("a validated macos-pf-load spec is accepted at the boundary");

        // ...but a macos-pf-load request whose interface token carries an
        // injected rule line is rejected before any render.
        let tampered = [
            "kind=killswitch",
            "generation=1",
            "strict=false",
            "interface=utun9\npass out quick all",
            "egress=en0",
            "dns_protected=false",
            "allow_egress_interface=false",
            "fail_closed_ssh_allow=false",
            "ipv6_blocked=false",
        ];
        assert!(validate_request(PrivilegedCommandProgram::MacosPfLoad, &tampered).is_err());
    }

    #[test]
    fn validate_request_rejects_path_traversal_in_pfctl_anchor_name() {
        assert!(!is_anchor_name_token("com.apple/rustynet_g1/../foo"));
        assert!(!is_anchor_name_token("com.apple/rustynet_g1/.."));
        assert!(is_anchor_name_token("com.apple/rustynet_g1"));
        assert!(is_anchor_name_token("com.rustynet/blind_exit"));
        // The regular exit NAT anchor is permitted, but nothing else under the
        // com.rustynet/ namespace and no traversal off it.
        assert!(is_anchor_name_token("com.rustynet/nat"));
        assert!(!is_anchor_name_token("com.rustynet/nat/.."));
        assert!(!is_anchor_name_token("com.rustynet/other"));
        let err = validate_request(
            PrivilegedCommandProgram::Pfctl,
            &[
                "-a",
                "com.apple/rustynet_g1/../escape",
                "-f",
                "/etc/rustynet/anchor.conf",
            ],
        )
        .expect_err("pfctl anchor traversal must be rejected");
        assert!(err.contains("unsupported pfctl argument schema"));
    }

    #[test]
    fn validate_sysctl_args_permits_only_exact_macos_forwarding_toggles() {
        // The regular exit NAT toggles + reads the macOS IPv4 AND IPv6
        // forwarding sysctls (one family per mesh prefix); only the exact
        // `=1`/`=0` writes and the `-n` reads are permitted. Everything else
        // stays default-denied.
        assert!(validate_sysctl_args(&["-w", "net.inet.ip.forwarding=1"]).is_ok());
        assert!(validate_sysctl_args(&["-w", "net.inet.ip.forwarding=0"]).is_ok());
        assert!(validate_sysctl_args(&["-n", "net.inet.ip.forwarding"]).is_ok());
        assert!(validate_sysctl_args(&["-w", "net.inet6.ip6.forwarding=1"]).is_ok());
        assert!(validate_sysctl_args(&["-w", "net.inet6.ip6.forwarding=0"]).is_ok());
        assert!(validate_sysctl_args(&["-n", "net.inet6.ip6.forwarding"]).is_ok());
        // Arbitrary values, a malformed/near-miss key, and write-of-read-key
        // must all be rejected — default-deny holds.
        for bad in [
            vec!["-w", "net.inet.ip.forwarding=2"],
            vec!["-w", "net.inet.ip.forwarding=on"],
            vec!["-w", "net.inet.ip.forwarding"],
            vec!["-w", "net.inet6.ip6.forwarding=2"],
            vec!["-w", "net.inet.ip6.forwarding=1"], // malformed: `inet` not `inet6`
            vec!["-n", "net.inet.ip.forwarding=1"],
        ] {
            assert!(
                validate_sysctl_args(&bad).is_err(),
                "sysctl args must be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_pfctl_args_permits_nat_anchor_show_and_flush_but_not_load() {
        // The exit NAT activation verifies + flushes the com.rustynet/nat anchor
        // via the still-allowed read/flush arms.
        assert!(validate_pfctl_args(&["-a", "com.rustynet/nat", "-F", "all"]).is_ok());
        assert!(validate_pfctl_args(&["-a", "com.rustynet/nat", "-s", "nat"]).is_ok());
        // Audit major #5: NO boundary-supplied `-f <path>` load is accepted on
        // ANY anchor, including the NAT anchor — rule loading goes exclusively
        // through the macos-pf-load builtin.
        assert!(validate_pfctl_args(&["-a", "com.rustynet/nat", "-f", "/tmp/nat.pf"]).is_err());
        assert!(validate_pfctl_args(&["-a", "com.apple/rustynet_g1", "-f", "/tmp/k.pf"]).is_err());
        assert!(
            validate_pfctl_args(&["-n", "-a", "com.rustynet/blind_exit", "-f", "/tmp/b.pf"])
                .is_err()
        );
        // A non-allowlisted anchor stays denied even for the read-only show.
        assert!(validate_pfctl_args(&["-a", "com.rustynet/other", "-s", "nat"]).is_err());
    }

    #[test]
    fn validate_request_rejects_unknown_program_failclosed() {
        // Unknown opcode/program names must never quietly fall through to a
        // default. handle_request takes the request directly so the error
        // surface is exercised end-to-end.
        let response = handle_request(HelperRequest {
            program: "totally-unknown-program".to_owned(),
            args: vec!["--version".to_owned()],
        });
        assert!(!response.ok);
        assert!(response.status.is_none());
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("unsupported privileged command program")
        );
    }

    #[test]
    fn helper_request_decoder_rejects_oversized_program_field() {
        // Length prefix declares a program field longer than MAX_PROGRAM_BYTES.
        let mut payload = Vec::new();
        let oversized_len: u16 = (super::MAX_PROGRAM_BYTES as u16) + 1;
        payload.extend_from_slice(&oversized_len.to_be_bytes());
        payload.extend(std::iter::repeat_n(b'a', oversized_len as usize));
        payload.extend_from_slice(&0u16.to_be_bytes());
        let err =
            decode_helper_request(&payload).expect_err("oversized program field must be rejected");
        assert!(err.contains("exceeds maximum size"));
    }

    #[test]
    fn validate_route_args_accepts_endpoint_bypass_with_and_without_ifscope() {
        // The macOS WireGuard backend installs endpoint bypass routes
        // in two reviewed shapes. Both must pass the helper's argv
        // whitelist; both must not require any other argument.
        super::validate_route_args(&[
            "-n",
            "add",
            "-inet",
            "-host",
            "192.168.65.3",
            "192.168.64.1",
        ])
        .expect("non-ifscope bypass form must be whitelisted");
        super::validate_route_args(&["-n", "add", "-inet6", "-host", "fd00::3", "fd00::1"])
            .expect("non-ifscope bypass form must support inet6");
        super::validate_route_args(&[
            "-n",
            "add",
            "-inet",
            "-host",
            "192.168.65.3",
            "192.168.64.1",
            "-ifscope",
            "en0",
        ])
        .expect("ifscope bypass form must remain whitelisted for legacy callers");
    }

    #[test]
    fn validate_route_args_rejects_endpoint_bypass_with_invalid_payload() {
        // Endpoint and gateway must both be IPs.
        super::validate_route_args(&["-n", "add", "-inet", "-host", "not-an-ip", "192.168.64.1"])
            .expect_err("non-IP endpoint must be rejected");
        super::validate_route_args(&["-n", "add", "-inet", "-host", "192.168.65.3", "not-an-ip"])
            .expect_err("non-IP gateway must be rejected");
    }
}
