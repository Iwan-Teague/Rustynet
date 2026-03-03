#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
use nix::unistd::{Gid, chown};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH: &str = "/run/rustynet/rustynetd-privileged.sock";
pub const DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS: u64 = 2_000;

const MAX_MESSAGE_BYTES: usize = 16_384;
const MAX_OUTPUT_BYTES: usize = 65_536;
const MAX_ARGS: usize = 128;
const MAX_ARG_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedCommandProgram {
    Ip,
    Nft,
    Wg,
    Sysctl,
}

impl PrivilegedCommandProgram {
    pub fn as_str(self) -> &'static str {
        match self {
            PrivilegedCommandProgram::Ip => "ip",
            PrivilegedCommandProgram::Nft => "nft",
            PrivilegedCommandProgram::Wg => "wg",
            PrivilegedCommandProgram::Sysctl => "sysctl",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(PrivilegedCommandProgram::Ip),
            "nft" => Some(PrivilegedCommandProgram::Nft),
            "wg" => Some(PrivilegedCommandProgram::Wg),
            "sysctl" => Some(PrivilegedCommandProgram::Sysctl),
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
        }
    }

    fn resolve_binary(self) -> Option<&'static str> {
        self.binary_candidates()
            .iter()
            .copied()
            .find(|candidate| Path::new(candidate).exists())
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
        let mut payload = serde_json::to_vec(&request)
            .map_err(|err| format!("privileged helper request encode failed: {err}"))?;
        payload.push(b'\n');
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err("privileged helper request exceeds maximum size".to_string());
        }
        stream
            .write_all(&payload)
            .map_err(|err| format!("privileged helper request write failed: {err}"))?;
        stream
            .flush()
            .map_err(|err| format!("privileged helper request flush failed: {err}"))?;

        let mut reader = BufReader::new(stream);
        let mut response_bytes = Vec::new();
        let read = reader
            .read_until(b'\n', &mut response_bytes)
            .map_err(|err| format!("privileged helper response read failed: {err}"))?;
        if read == 0 {
            return Err("privileged helper closed connection without a response".to_string());
        }
        if response_bytes.len() > MAX_MESSAGE_BYTES {
            return Err("privileged helper response exceeds maximum size".to_string());
        }

        let response = serde_json::from_slice::<HelperResponse>(&response_bytes)
            .map_err(|err| format!("privileged helper response decode failed: {err}"))?;
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
            Ok(request) => handle_request(request),
            Err(err) => HelperResponse::error(err),
        };
        let _ = write_response(&mut stream, response);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HelperRequest {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    let mut reader = BufReader::new(stream);
    let mut request_bytes = Vec::new();
    let read = reader
        .read_until(b'\n', &mut request_bytes)
        .map_err(|err| format!("read request failed: {err}"))?;
    if read == 0 {
        return Err("empty request".to_string());
    }
    if request_bytes.len() > MAX_MESSAGE_BYTES {
        return Err("request exceeds maximum size".to_string());
    }
    serde_json::from_slice::<HelperRequest>(&request_bytes)
        .map_err(|err| format!("request decode failed: {err}"))
}

fn write_response(stream: &mut UnixStream, response: HelperResponse) -> Result<(), String> {
    let mut response_bytes =
        serde_json::to_vec(&response).map_err(|err| format!("encode response failed: {err}"))?;
    response_bytes.push(b'\n');
    if response_bytes.len() > MAX_MESSAGE_BYTES {
        return Err("response exceeds maximum size".to_string());
    }
    stream
        .write_all(&response_bytes)
        .map_err(|err| format!("write response failed: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("flush response failed: {err}"))
}

fn handle_request(request: HelperRequest) -> HelperResponse {
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
        Some(path) => path,
        None => {
            return HelperResponse::error(format!(
                "no supported binary path found for {}",
                program
            ));
        }
    };

    match Command::new(binary).args(&request.args).output() {
        Ok(output) => {
            let status = output.status.code().unwrap_or(-1);
            let stdout = truncate_lossy(&output.stdout, MAX_OUTPUT_BYTES);
            let stderr = truncate_lossy(&output.stderr, MAX_OUTPUT_BYTES);
            HelperResponse::success(status, stdout, stderr)
        }
        Err(err) => HelperResponse::error(format!(
            "{} command spawn failed ({}): {err}",
            program, binary
        )),
    }
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
            "too many arguments for privileged command {}",
            program
        ));
    }
    for arg in args {
        if arg.is_empty() {
            return Err(format!("empty argument in privileged command {}", program));
        }
        if arg.len() > MAX_ARG_BYTES {
            return Err(format!(
                "argument too long in privileged command {}",
                program
            ));
        }
        if !is_safe_token(arg) {
            return Err(format!(
                "unsupported argument token '{}' in privileged command {}",
                arg, program
            ));
        }
    }
    Ok(())
}

fn is_safe_token(value: &str) -> bool {
    value.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '-' | '_' | '.' | '/' | ':' | ',' | '=' | '{' | '}' | ';' | '!' | '+'
            )
    })
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
    use super::{PrivilegedCommandProgram, is_safe_token, validate_request};

    #[test]
    fn privileged_program_parser_rejects_unknown() {
        assert!(PrivilegedCommandProgram::parse("nft").is_some());
        assert!(PrivilegedCommandProgram::parse("not-real").is_none());
    }

    #[test]
    fn safe_token_rejects_unsafe_characters() {
        assert!(is_safe_token("established,related"));
        assert!(is_safe_token("!="));
        assert!(!is_safe_token("$(id)"));
        assert!(!is_safe_token("a|b"));
        assert!(!is_safe_token("contains space"));
    }

    #[test]
    fn validate_request_rejects_invalid_tokens() {
        let err = validate_request(
            PrivilegedCommandProgram::Nft,
            &["list", "table", "inet", "$(id)"],
        )
        .expect_err("unsafe token should be rejected");
        assert!(err.contains("unsupported argument token"));
    }
}
