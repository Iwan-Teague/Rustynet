#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
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
    if args.is_empty() {
        return Err(format!(
            "missing arguments for privileged command {}",
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
    use super::{PrivilegedCommandProgram, is_nft_token, is_safe_token, validate_request};

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
    fn validate_request_accepts_known_nft_list_table_schema() {
        validate_request(
            PrivilegedCommandProgram::Nft,
            &["list", "table", "inet", "rustynet_g1"],
        )
        .expect("known nft list table schema should be accepted");
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
}
