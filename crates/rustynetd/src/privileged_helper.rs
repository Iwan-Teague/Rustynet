#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

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
use nix::unistd::{Gid, Group, Uid, chown};
use rustynet_local_security::{
    validate_owner_only_socket, validate_root_managed_shared_runtime_socket,
};

pub const DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH: &str = "/run/rustynet/rustynetd-privileged.sock";
pub const DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS: u64 = 2_000;

const HELPER_FRAME_MAGIC: [u8; 4] = *b"RNHF";
const HELPER_FRAME_VERSION: u8 = 1;
const HELPER_FRAME_TYPE_REQUEST: u8 = 1;
const HELPER_FRAME_TYPE_RESPONSE: u8 = 2;
const HELPER_FRAME_HEADER_BYTES: usize = 10;
const MAX_MESSAGE_BYTES: usize = 16_384;
const MAX_OUTPUT_BYTES: usize = 65_536;
const MAX_ARGS: usize = 128;
const MAX_ARG_BYTES: usize = 256;
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
        }
    }

    fn parse(value: &str) -> Option<Self> {
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
            _ => None,
        }
    }

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
        }
    }

    fn resolve_binary(self) -> Result<PathBuf, String> {
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
            return Err("privileged helper socket path must not be empty".to_string());
        }
        if !socket_path.is_absolute() {
            return Err("privileged helper socket path must be absolute".to_string());
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

        let request = HelperRequest {
            program: program.as_str().to_string(),
            args: args
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        };
        write_request_frame(&mut stream, &request)?;
        let response = read_response_frame(&mut stream)?;
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| "privileged helper reported an unknown failure".to_string()));
        }
        Ok(PrivilegedCommandOutput {
            status: response.status.unwrap_or(-1),
            stdout: response.stdout.unwrap_or_default(),
            stderr: response.stderr.unwrap_or_default(),
        })
    }
}

fn rustynetd_service_gid_for_socket(path: &Path) -> Option<u32> {
    if !path.starts_with("/run/rustynet") {
        return None;
    }
    Group::from_name("rustynetd")
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

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
        return Err("privileged helper socket path must not be empty".to_string());
    }
    if !config.socket_path.is_absolute() {
        return Err("privileged helper socket path must be absolute".to_string());
    }

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
        fs::set_permissions(parent, fs::Permissions::from_mode(parent_mode)).map_err(|err| {
            format!(
                "set privileged helper socket parent permissions {} failed: {err}",
                parent.display()
            )
        })?;
    }

    if config.socket_path.exists() {
        let metadata = fs::symlink_metadata(&config.socket_path).map_err(|err| {
            format!(
                "inspect existing privileged helper socket {} failed: {err}",
                config.socket_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err("privileged helper socket path must not be a symlink".to_string());
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
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660)).map_err(|err| {
        format!(
            "set privileged helper socket permissions {} failed: {err}",
            config.socket_path.display()
        )
    })?;
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

        let authorized = peer_uid(&stream)
            .map(|uid| uid == config.allowed_uid || uid == 0)
            .unwrap_or(false);
        if !authorized {
            let _ = write_response(
                &mut stream,
                HelperResponse::error("unauthorized privileged helper peer".to_string()),
            );
            continue;
        }

        let response = match read_request(&mut stream) {
            Ok(request) => handle_request_with_timeout(request, config.io_timeout),
            Err(err) => HelperResponse::error(err),
        };
        let _ = write_response(&mut stream, response);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperRequest {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperResponse {
    ok: bool,
    status: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

impl HelperResponse {
    fn error(message: String) -> Self {
        Self {
            ok: false,
            status: None,
            stdout: None,
            stderr: None,
            error: Some(message),
        }
    }

    fn success(status: i32, stdout: String, stderr: String) -> Self {
        Self {
            ok: true,
            status: Some(status),
            stdout: Some(stdout),
            stderr: Some(stderr),
            error: None,
        }
    }
}

fn read_request(stream: &mut UnixStream) -> Result<HelperRequest, String> {
    let request_bytes = read_frame(stream, HELPER_FRAME_TYPE_REQUEST)?;
    decode_helper_request(&request_bytes).map_err(|err| format!("request decode failed: {err}"))
}

fn write_response(stream: &mut UnixStream, response: HelperResponse) -> Result<(), String> {
    let response_bytes = encode_helper_response(&response)
        .map_err(|err| format!("encode response failed: {err}"))?;
    write_frame(stream, HELPER_FRAME_TYPE_RESPONSE, &response_bytes)
}

fn write_request_frame(stream: &mut UnixStream, request: &HelperRequest) -> Result<(), String> {
    let request_bytes = encode_helper_request(request)
        .map_err(|err| format!("privileged helper request encode failed: {err}"))?;
    write_frame(stream, HELPER_FRAME_TYPE_REQUEST, &request_bytes)
        .map_err(|err| format!("privileged helper request write failed: {err}"))
}

fn read_response_frame(stream: &mut UnixStream) -> Result<HelperResponse, String> {
    let response_bytes = read_frame(stream, HELPER_FRAME_TYPE_RESPONSE)
        .map_err(|err| format!("privileged helper response read failed: {err}"))?;
    decode_helper_response(&response_bytes)
        .map_err(|err| format!("privileged helper response decode failed: {err}"))
}

fn write_frame(stream: &mut UnixStream, message_type: u8, payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("frame payload must not be empty".to_string());
    }
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err("frame payload exceeds maximum size".to_string());
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| "frame payload length overflow".to_string())?;
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

fn read_frame(stream: &mut UnixStream, expected_message_type: u8) -> Result<Vec<u8>, String> {
    let mut header = [0u8; HELPER_FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut header)
        .map_err(|err| map_read_exact_error(err, "frame header"))?;
    if header[..4] != HELPER_FRAME_MAGIC {
        return Err("invalid frame magic".to_string());
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
        return Err("frame payload must not be empty".to_string());
    }
    if payload_len > MAX_MESSAGE_BYTES {
        return Err("frame payload exceeds maximum size".to_string());
    }
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| map_read_exact_error(err, "frame payload"))?;
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(payload),
        Ok(_) => Err("trailing bytes after frame payload".to_string()),
        Err(err) => Err(format!("read frame trailer failed: {err}")),
    }
}

fn map_read_exact_error(err: std::io::Error, label: &str) -> String {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return format!("truncated {label}");
    }
    format!("read {label} failed: {err}")
}

fn encode_helper_request(request: &HelperRequest) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    encode_string_field(
        &mut payload,
        request.program.as_str(),
        "program",
        MAX_PROGRAM_BYTES,
    )?;
    let arg_count = u16::try_from(request.args.len())
        .map_err(|_| "argument count exceeds protocol limit".to_string())?;
    payload.extend_from_slice(&arg_count.to_be_bytes());
    for arg in &request.args {
        encode_string_field(&mut payload, arg.as_str(), "arg", MAX_ARG_BYTES)?;
    }
    Ok(payload)
}

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

fn encode_helper_response(response: &HelperResponse) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    payload.push(u8::from(response.ok));
    encode_optional_i32(&mut payload, response.status);
    encode_optional_string_field(&mut payload, response.stdout.as_deref(), "stdout")?;
    encode_optional_string_field(&mut payload, response.stderr.as_deref(), "stderr")?;
    encode_optional_string_field(&mut payload, response.error.as_deref(), "error")?;
    Ok(payload)
}

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

fn encode_optional_i32(payload: &mut Vec<u8>, value: Option<i32>) {
    match value {
        Some(value) => {
            payload.push(1);
            payload.extend_from_slice(&value.to_be_bytes());
        }
        None => payload.push(0),
    }
}

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

fn decode_bool(payload: &[u8], cursor: &mut usize, label: &str) -> Result<bool, String> {
    match decode_u8(payload, cursor, label)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(format!("invalid {label} flag {value}")),
    }
}

fn decode_bool_flag(payload: &[u8], cursor: &mut usize, label: &str) -> Result<bool, String> {
    decode_bool(payload, cursor, label)
}

fn decode_u8(payload: &[u8], cursor: &mut usize, label: &str) -> Result<u8, String> {
    let byte = *payload
        .get(*cursor)
        .ok_or_else(|| format!("truncated {label}"))?;
    *cursor += 1;
    Ok(byte)
}

fn decode_u16(payload: &[u8], cursor: &mut usize, label: &str) -> Result<u16, String> {
    let bytes = decode_fixed::<2>(payload, cursor, label)?;
    Ok(u16::from_be_bytes(bytes))
}

fn decode_i32(payload: &[u8], cursor: &mut usize, label: &str) -> Result<i32, String> {
    let bytes = decode_fixed::<4>(payload, cursor, label)?;
    Ok(i32::from_be_bytes(bytes))
}

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

fn ensure_payload_consumed(payload: &[u8], cursor: usize) -> Result<(), String> {
    if cursor != payload.len() {
        return Err("trailing bytes after helper payload".to_string());
    }
    Ok(())
}

#[cfg(test)]
fn handle_request(request: HelperRequest) -> HelperResponse {
    handle_request_with_timeout(
        request,
        Duration::from_millis(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS),
    )
}

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

fn exit_status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

fn truncate_lossy(bytes: &[u8], max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        return String::from_utf8_lossy(bytes).to_string();
    }
    let mut out = String::from_utf8_lossy(&bytes[..max_bytes]).to_string();
    out.push_str("...[truncated]");
    out
}

fn validate_request(program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), String> {
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
    }
}

fn is_safe_token(value: &str) -> bool {
    value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | ',' | '=' | '+')
    })
}

#[cfg(test)]
fn is_nft_token(value: &str) -> bool {
    matches!(value, "{" | "}" | ";" | "!=") || is_safe_token(value)
}

fn is_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn is_path_token(value: &str) -> bool {
    value.starts_with('/') && is_safe_token(value)
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

fn is_anchor_name_token(value: &str) -> bool {
    value.starts_with("com.apple/rustynet_g")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.'))
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
        _ => Err("unsupported nft add chain argument schema".to_string()),
    }
}

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
        _ => Err("unsupported nft add rule argument schema".to_string()),
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
        ["route", "get", target] if is_ipv4_or_ipv6(target) => Ok(()),
        ["-6", "route", "get", target] if target.parse::<std::net::Ipv6Addr>().is_ok() => Ok(()),
        ["rule", "del", "table", "51820"] => Ok(()),
        ["rule", "del", "priority", priority, "table", "51820"] if is_u32_token(priority) => Ok(()),
        ["rule", "add", "priority", priority, "table", "51820"] if is_u32_token(priority) => Ok(()),
        _ => Err("unsupported ip argument schema".to_string()),
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
        _ if args.starts_with(&["add", "chain"]) => validate_nft_add_chain_args(args),
        _ if args.starts_with(&["add", "rule"]) => validate_nft_add_rule_args(args),
        _ => Err("unsupported nft argument schema".to_string()),
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
        ["set", interface, "peer", public_key, "remove"]
            if is_interface_name(interface) && is_wg_public_key_token(public_key) =>
        {
            Ok(())
        }
        _ => Err("unsupported wg argument schema".to_string()),
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
        _ => Err("unsupported sysctl argument schema".to_string()),
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
        _ => Err("unsupported ifconfig argument schema".to_string()),
    }
}

fn validate_route_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-n", "get", "default"] => Ok(()),
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
        _ => Err("unsupported route argument schema".to_string()),
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
        ["-a", anchor, "-f", path] if is_anchor_name_token(anchor) && is_path_token(path) => Ok(()),
        ["-a", anchor, "-s", "rules"] if is_anchor_name_token(anchor) => Ok(()),
        _ => Err("unsupported pfctl argument schema".to_string()),
    }
}

fn validate_wireguard_go_args(args: &[&str]) -> Result<(), String> {
    match args {
        [interface] if is_interface_name(interface) => Ok(()),
        _ => Err("unsupported wireguard-go argument schema".to_string()),
    }
}

fn validate_kill_args(args: &[&str]) -> Result<(), String> {
    match args {
        ["-TERM", pid] if pid.parse::<u32>().map(|value| value > 1).unwrap_or(false) => Ok(()),
        _ => Err("unsupported kill argument schema".to_string()),
    }
}

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
    {
        return getsockopt(stream, LocalPeerCred)
            .ok()
            .map(|cred| cred.uid());
    }

    #[allow(unreachable_code)]
    None
}

impl fmt::Display for PrivilegedCommandProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        HELPER_FRAME_MAGIC, HELPER_FRAME_TYPE_REQUEST, HELPER_FRAME_VERSION, HelperRequest,
        HelperResponse, MAX_ARG_BYTES, MAX_ARGS, MAX_MESSAGE_BYTES, PrivilegedCommandProgram,
        encode_helper_request, handle_request, is_nft_token, is_safe_token, read_request,
        read_response_frame, run_privileged_subprocess, validate_privileged_helper_socket_security,
        validate_privileged_program_binary, validate_request, write_request_frame, write_response,
    };

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
    fn helper_frame_rejects_invalid_magic() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let payload = encode_helper_request(&HelperRequest {
            program: "ip".to_string(),
            args: vec!["--version".to_string()],
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
            program: "ip".to_string(),
            args: vec!["--version".to_string()],
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

    #[test]
    fn helper_frame_rejects_trailing_payload_bytes() {
        let (mut server_stream, mut client_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        server_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout should be set");

        let mut payload = encode_helper_request(&HelperRequest {
            program: "ip".to_string(),
            args: vec!["--version".to_string()],
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
            assert_eq!(request.args, vec!["--version".to_string()]);
            write_response(
                &mut server_stream,
                HelperResponse::success(0, "ok".to_string(), String::new()),
            )
            .expect("response should encode");
        });

        write_request_frame(
            &mut client_stream,
            &HelperRequest {
                program: "ip".to_string(),
                args: vec!["--version".to_string()],
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
            program: "not-a-real-program".to_string(),
            args: vec!["--version".to_string()],
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
                program: "ip".to_string(),
                args: vec!["link".to_string()],
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
                program: "not-real".to_string(),
                args: vec!["--version".to_string()],
            },
            HelperRequest {
                program: "ip".to_string(),
                args: vec![],
            },
            HelperRequest {
                program: "ip".to_string(),
                args: vec![
                    "route".to_string(),
                    "replace".to_string(),
                    "0.0.0.0/0".to_string(),
                    "via".to_string(),
                    "203.0.113.1".to_string(),
                ],
            },
            HelperRequest {
                program: "nft".to_string(),
                args: vec![
                    "list".to_string(),
                    "table".to_string(),
                    "inet".to_string(),
                    "$(id)".to_string(),
                ],
            },
            HelperRequest {
                program: "kill".to_string(),
                args: vec!["-TERM".to_string(), "1".to_string()],
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
            &["-c".to_string(), "sleep 1".to_string()],
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
}
