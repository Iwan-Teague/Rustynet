#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::live_lab_results::{LiveLabWorkerResult, read_parallel_stage_results};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const CHECK_PASS: &str = "pass";
const CHECK_FAIL: &str = "fail";
const CHECK_SKIPPED: &str = "skipped";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLocalFileModeConfig {
    pub path: PathBuf,
    pub policy: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteCrossNetworkForensicsManifestConfig {
    pub stage: String,
    pub collected_at_utc: String,
    pub stage_dir: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLabStageArtifactIndexConfig {
    pub stage_name: String,
    pub stage_dir: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateCrossNetworkForensicsBundleConfig {
    pub nodes_tsv: PathBuf,
    pub stage_name: String,
    pub stage_dir: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256FileConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteCrossNetworkPreflightReportConfig {
    pub nodes_tsv: PathBuf,
    pub stage_dir: PathBuf,
    pub output: PathBuf,
    pub reference_unix: u64,
    pub max_clock_skew_secs: u64,
    pub discovery_max_age_secs: u64,
    pub signed_artifact_max_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLinuxRebootRecoveryReportConfig {
    pub report_path: PathBuf,
    pub observations_path: PathBuf,
    pub exit_pre: String,
    pub exit_post: String,
    pub client_pre: String,
    pub client_post: String,
    pub exit_return: String,
    pub exit_boot_change: String,
    pub post_exit_dns_refresh: String,
    pub post_exit_twohop: String,
    pub client_return: String,
    pub client_boot_change: String,
    pub post_client_dns_refresh: String,
    pub post_client_twohop: String,
    pub salvage_twohop: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLinuxLabRunSummaryConfig {
    pub nodes_tsv: PathBuf,
    pub stages_tsv: PathBuf,
    pub summary_json: PathBuf,
    pub summary_md: PathBuf,
    pub run_id: String,
    pub network_id: String,
    pub report_dir: String,
    pub overall_status: String,
    pub started_at_local: String,
    pub started_at_utc: String,
    pub started_at_unix: u64,
    pub finished_at_local: String,
    pub finished_at_utc: String,
    pub finished_at_unix: u64,
    pub elapsed_secs: u64,
    pub elapsed_human: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanIpv4PortRangeConfig {
    pub network_prefix: String,
    pub start_host: u8,
    pub end_host: u8,
    pub port: u16,
    pub timeout_ms: u64,
    pub output_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRoleSwitchHostResultConfig {
    pub hosts_json_path: PathBuf,
    pub os_id: String,
    pub temp_role: String,
    pub switch_execution: String,
    pub post_switch_reconcile: String,
    pub policy_still_enforced: String,
    pub least_privilege_preserved: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRoleSwitchMatrixReportConfig {
    pub hosts_json_path: PathBuf,
    pub report_path: PathBuf,
    pub source_path: PathBuf,
    pub git_commit: String,
    pub captured_at_unix: u64,
    pub overall_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLinuxServerIpBypassReportConfig {
    pub report_path: PathBuf,
    pub allowed_management_cidrs: String,
    pub probe_from_client_status: String,
    pub probe_ip: String,
    pub probe_port: u16,
    pub client_internet_route: String,
    pub client_probe_route: String,
    pub client_table_51820: String,
    pub client_endpoints: String,
    pub probe_self_test: String,
    pub probe_from_client_output: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLinuxControlSurfaceReportConfig {
    pub report_path: PathBuf,
    pub dns_bind_addr: String,
    pub remote_dns_probe_status: String,
    pub remote_dns_probe_output: String,
    pub work_dir: PathBuf,
    pub host_labels: Vec<String>,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteAssignmentPeerEndpointIpConfig {
    pub assignment_path: PathBuf,
    pub endpoint_ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteAssignmentMeshCidrConfig {
    pub assignment_path: PathBuf,
    pub mesh_cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLiveLinuxEndpointHijackReportConfig {
    pub report_path: PathBuf,
    pub rogue_endpoint_ip: String,
    pub baseline_status: String,
    pub baseline_netcheck: String,
    pub baseline_endpoints: String,
    pub status_after_hijack: String,
    pub netcheck_after_hijack: String,
    pub endpoints_after_hijack: String,
    pub status_after_recovery: String,
    pub endpoints_after_recovery: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRealWireguardExitnodeE2eReportConfig {
    pub report_path: PathBuf,
    pub exit_status: String,
    pub lan_off_status: String,
    pub lan_on_status: String,
    pub dns_up_status: String,
    pub kill_switch_status: String,
    pub dns_down_status: String,
    pub environment: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRealWireguardNoLeakUnderLoadReportConfig {
    pub report_path: PathBuf,
    pub load_pcap: PathBuf,
    pub down_pcap: PathBuf,
    pub tunnel_up_status: String,
    pub load_ping_status: String,
    pub tunnel_down_block_status: String,
    pub environment: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyNoLeakDataplaneReportConfig {
    pub report_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eDnsQueryConfig {
    pub server: String,
    pub port: u16,
    pub qname: String,
    pub timeout_ms: u64,
    pub fail_on_no_response: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eHttpProbeServerConfig {
    pub bind_ip: String,
    pub port: u16,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eHttpProbeClientConfig {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u64,
    pub expect_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadJsonFieldConfig {
    pub payload: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractManagedDnsExpectedIpConfig {
    pub fqdn: String,
    pub inspect_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteActiveNetworkSignedStateTamperReportConfig {
    pub report_path: PathBuf,
    pub baseline_status: String,
    pub tamper_reject_status: String,
    pub fail_closed_status: String,
    pub netcheck_fail_closed_status: String,
    pub recovery_status: String,
    pub exit_host: String,
    pub client_host: String,
    pub status_after_tamper: String,
    pub netcheck_after_tamper: String,
    pub status_after_recovery: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteActiveNetworkRoguePathHijackReportConfig {
    pub report_path: PathBuf,
    pub baseline_status: String,
    pub hijack_reject_status: String,
    pub fail_closed_status: String,
    pub netcheck_fail_closed_status: String,
    pub no_rogue_endpoint_status: String,
    pub recovery_status: String,
    pub recovery_endpoint_status: String,
    pub rogue_endpoint_ip: String,
    pub exit_host: String,
    pub client_host: String,
    pub endpoints_before: String,
    pub endpoints_after_hijack: String,
    pub endpoints_after_recovery: String,
    pub status_after_hijack: String,
    pub netcheck_after_hijack: String,
    pub status_after_recovery: String,
    pub captured_at_utc: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileModePolicy {
    OwnerOnly,
    NoGroupWorldWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

fn parse_file_mode_policy(raw: &str) -> Result<FileModePolicy, String> {
    match raw.trim() {
        "owner-only" => Ok(FileModePolicy::OwnerOnly),
        "no-group-world-write" => Ok(FileModePolicy::NoGroupWorldWrite),
        other => Err(format!(
            "invalid --policy {other:?}; expected owner-only or no-group-world-write"
        )),
    }
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn read_tsv_rows(path: &Path) -> Result<Vec<Vec<String>>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read tsv failed ({}): {err}", path.display()))?;
    Ok(body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split('\t')
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>())
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn write_json_pretty(path: &Path, payload: &Value) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let body = serde_json::to_string_pretty(payload)
        .map_err(|err| format!("serialize JSON failed: {err}"))?;
    fs::write(path, format!("{body}\n"))
        .map_err(|err| format!("write JSON failed ({}): {err}", path.display()))
}

fn absolute_path_string(path: &Path) -> Result<String, String> {
    Ok(resolve_path(path)?.display().to_string())
}

fn is_word_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(value) => !(value.is_ascii_alphanumeric() || value == '_'),
    }
}

fn redact_first_keyword_value(line: &str, keyword: &str) -> Option<String> {
    let lowered = line.to_ascii_lowercase();
    let keyword_len = keyword.len();
    let mut search_from = 0usize;
    while search_from + keyword_len <= lowered.len() {
        let offset = lowered[search_from..].find(keyword)?;
        let start = search_from + offset;
        let end = start + keyword_len;
        let before = line[..start].chars().next_back();
        let after = line[end..].chars().next();
        if !is_word_boundary(before) || !is_word_boundary(after) {
            search_from = end;
            continue;
        }
        let bytes = line.as_bytes();
        let mut sep_index = end;
        while sep_index < bytes.len() && bytes[sep_index].is_ascii_whitespace() {
            sep_index += 1;
        }
        if sep_index >= bytes.len() || !matches!(bytes[sep_index], b':' | b'=') {
            search_from = end;
            continue;
        }
        let mut value_start = sep_index + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start >= bytes.len() {
            return None;
        }
        let mut value_end = value_start;
        while value_end < bytes.len() && !bytes[value_end].is_ascii_whitespace() {
            value_end += 1;
        }
        let mut out = String::with_capacity(line.len());
        out.push_str(&line[..value_start]);
        out.push_str("<redacted>");
        out.push_str(&line[value_end..]);
        return Some(out);
    }
    None
}

fn redact_forensics_line(line: &str) -> String {
    let upper = line.to_ascii_uppercase();
    if upper.contains("PRIVATE KEY-----")
        || (upper.contains("BEGIN ") && upper.contains("PRIVATE KEY"))
    {
        return "[REDACTED sensitive key material]".to_string();
    }
    let mut out = line.to_string();
    for keyword in ["passphrase", "password", "secret", "token"] {
        if let Some(updated) = redact_first_keyword_value(out.as_str(), keyword) {
            out = updated;
        }
    }
    out
}

fn redact_forensics_payload(input: &str) -> String {
    let mut lines = input
        .lines()
        .map(redact_forensics_line)
        .collect::<Vec<String>>();
    if lines.is_empty() {
        return String::new();
    }
    let mut body = lines.join("\n");
    if input.ends_with('\n') {
        body.push('\n');
    }
    lines.clear();
    body
}

fn parse_network_prefix(prefix: &str) -> Result<[u8; 3], String> {
    let parts = prefix.trim().split('.').map(str::trim).collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(format!(
            "invalid --network-prefix {prefix:?}; expected a.b.c"
        ));
    }
    let mut octets = [0u8; 3];
    for (index, part) in parts.iter().enumerate() {
        octets[index] = part
            .parse::<u8>()
            .map_err(|err| format!("invalid --network-prefix {prefix:?}: {err}"))?;
    }
    Ok(octets)
}

fn reboot_reason_for_check(check: &str) -> Option<&'static str> {
    match check {
        "exit_reboot_returns" => Some("exit did not return on SSH after reboot"),
        "exit_boot_id_changes" => Some("exit reboot was not proven by a new boot_id"),
        "post_exit_reboot_managed_dns_refresh" => {
            Some("managed DNS refresh failed after exit reboot")
        }
        "post_exit_reboot_twohop" => Some("two-hop validation failed after exit reboot"),
        "client_reboot_returns" => Some("client did not return on SSH after reboot"),
        "client_boot_id_changes" => Some("client reboot was not proven by a new boot_id"),
        "post_client_reboot_managed_dns_refresh" => {
            Some("managed DNS refresh failed after client reboot")
        }
        "post_client_reboot_twohop" => Some("two-hop validation failed after client reboot"),
        "client_failure_salvage_twohop" => {
            Some("salvage two-hop validation failed after the client reboot outage")
        }
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collected_at_utc_now() -> String {
    Command::new("date")
        .arg("-u")
        .arg("+%FT%TZ")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| format!("unix:{}", unix_now()))
}

fn sha256_hex_for_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("read file failed ({}): {err}", path.display()))?;
    let digest = Sha256::digest(bytes.as_slice());
    Ok(format!("{digest:x}"))
}

fn walk_stage_files_recursive(
    root: &Path,
    current: &Path,
    excluded_output: Option<&Path>,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|err| format!("read directory failed ({}): {err}", current.display()))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let resolved = resolve_path(path.as_path())?;
        if excluded_output == Some(resolved.as_path()) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|err| format!("read file type failed ({}): {err}", entry.path().display()))?;
        if file_type.is_dir() {
            walk_stage_files_recursive(root, resolved.as_path(), excluded_output, files)?;
            continue;
        }
        if file_type.is_file() {
            if !resolved.starts_with(root) {
                return Err(format!(
                    "stage artifact escaped stage root: {} not under {}",
                    resolved.display(),
                    root.display()
                ));
            }
            files.push(resolved);
            continue;
        }
        if file_type.is_symlink() {
            return Err(format!(
                "stage artifact must not be a symlink: {}",
                resolved.display()
            ));
        }
        return Err(format!(
            "unsupported stage artifact type: {}",
            resolved.display()
        ));
    }
    Ok(())
}

fn expected_forensics_node_files() -> &'static [&'static str] {
    &[
        "service_snapshot.txt",
        "network_snapshot.txt",
        "route_policy.txt",
        "dns_state.txt",
        "time_snapshot.txt",
        "process_snapshot.txt",
        "socket_snapshot.txt",
        "permissions_snapshot.txt",
        "firewall.txt",
        "dns_zone.txt",
        "signed_state.txt",
        "secret_hygiene.txt",
        "node_snapshot.txt",
        "node_identity.txt",
    ]
}

fn parse_pass_fail(value: &str, label: &str) -> Result<String, String> {
    let normalized = value.trim();
    if normalized == CHECK_PASS || normalized == CHECK_FAIL {
        Ok(normalized.to_string())
    } else {
        Err(format!("{label} must be pass or fail (got: {value:?})"))
    }
}

fn parse_pass_fail_skip(value: &str, label: &str) -> Result<String, String> {
    let normalized = value.trim();
    if normalized == CHECK_PASS || normalized == CHECK_FAIL || normalized == CHECK_SKIPPED {
        Ok(normalized.to_string())
    } else {
        Err(format!(
            "{label} must be pass, fail, or skipped (got: {value:?})"
        ))
    }
}

fn decode_tcpdump_lines(path: &Path) -> Result<Vec<String>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("stat pcap failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "pcap path must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "pcap path must be a regular file: {}",
            path.display()
        ));
    }
    let output = Command::new("tcpdump")
        .arg("-nn")
        .arg("-r")
        .arg(path)
        .output()
        .map_err(|err| format!("tcpdump decode failed ({}): {err}", path.display()))?;
    if !output.status.success() && output.status.code() != Some(1) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "tcpdump decode failed ({}): {}",
            path.display(),
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("decode tcpdump output failed ({}): {err}", path.display()))?;
    Ok(stdout.lines().map(ToString::to_string).collect())
}

fn count_no_leak_tunnel_packets(lines: &[String]) -> u64 {
    lines
        .iter()
        .filter(|line| {
            line.contains("IP 172.16.10.2.") && line.contains(" > 172.16.10.1.51820: UDP")
        })
        .count() as u64
}

fn count_no_leak_cleartext_packets(lines: &[String]) -> u64 {
    lines
        .iter()
        .filter(|line| line.contains("IP 172.16.10.2") && line.contains(" > 198.18.0.1"))
        .count() as u64
}

fn validate_dns_qname(raw: &str) -> Result<String, String> {
    let qname = raw.trim().trim_end_matches('.').to_string();
    if qname.is_empty() {
        return Err("qname must not be empty".to_string());
    }
    if qname.len() > 253 {
        return Err("qname exceeds maximum DNS length".to_string());
    }
    for label in qname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS label length in qname: {label:?}"));
        }
        if !label.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'
            )
        }) {
            return Err(format!("invalid DNS label in qname: {label:?}"));
        }
    }
    Ok(qname)
}

fn build_dns_query_packet(qname: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);
    packet.extend_from_slice(&0x1337u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, String> {
    let mut labels_seen = 0usize;
    loop {
        if offset >= packet.len() {
            return Err("dns response truncated while reading name".to_string());
        }
        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            if offset + 1 >= packet.len() {
                return Err("dns response truncated while reading compression pointer".to_string());
            }
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0b1100_0000 != 0 {
            return Err("dns response contains invalid label encoding".to_string());
        }
        let label_len = len as usize;
        if label_len > 63 {
            return Err("dns response contains oversized label".to_string());
        }
        offset += 1;
        if offset + label_len > packet.len() {
            return Err("dns response truncated while reading label bytes".to_string());
        }
        offset += label_len;
        labels_seen += 1;
        if labels_seen > 128 {
            return Err("dns response name parse exceeded label limit".to_string());
        }
    }
}

fn decode_first_dns_answer(
    response: &[u8],
    rcode: i64,
    answer_count: u64,
) -> Result<(i64, u64, String, u64), String> {
    if response.len() < 12 {
        return Err("dns response header is too short".to_string());
    }
    let mut offset = 12usize;
    offset = skip_dns_name(response, offset)?;
    if offset + 4 > response.len() {
        return Err("dns response truncated in question tail".to_string());
    }
    offset += 4;

    let mut answer_ip = String::new();
    let mut answer_ttl = 0u64;
    if answer_count > 0 {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err("dns response truncated in answer header".to_string());
        }
        let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rr_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let ttl = u32::from_be_bytes([
            response[offset + 4],
            response[offset + 5],
            response[offset + 6],
            response[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > response.len() {
            return Err("dns response truncated in answer payload".to_string());
        }
        if rr_type == 1 && rr_class == 1 && rdlen == 4 {
            let addr = Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            );
            answer_ip = addr.to_string();
            answer_ttl = ttl as u64;
        }
    }
    Ok((rcode, answer_count, answer_ip, answer_ttl))
}

fn is_plaintext_no_leak_report(payload: &Map<String, Value>) -> Result<(), String> {
    if payload.get("status").and_then(Value::as_str) != Some(CHECK_PASS) {
        return Err("no-leak dataplane report status must be pass".to_string());
    }
    let checks = payload
        .get("checks")
        .and_then(Value::as_object)
        .ok_or_else(|| "no-leak dataplane report must contain non-empty checks".to_string())?;
    if checks.is_empty() {
        return Err("no-leak dataplane report must contain non-empty checks".to_string());
    }
    let failed = checks
        .iter()
        .filter_map(|(key, value)| {
            if value.as_str() == Some(CHECK_PASS) {
                None
            } else {
                Some(key.clone())
            }
        })
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "no-leak dataplane checks failed: {}",
            failed.join(", ")
        ))
    }
}

fn read_json_object_or_empty(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read JSON failed ({}): {err}", path.display()))?;
    if body.trim().is_empty() {
        return Ok(Map::new());
    }
    let parsed: Value = serde_json::from_str(body.as_str())
        .map_err(|err| format!("parse JSON failed ({}): {err}", path.display()))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| format!("JSON root must be an object ({})", path.display()))?;
    Ok(object.clone())
}

fn parse_cidr(value: &str) -> Result<ParsedCidr, String> {
    let trimmed = value.trim();
    let (ip_raw, prefix_raw) = trimmed
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR {trimmed:?}"))?;
    let ip = ip_raw
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid CIDR IP {ip_raw:?}: {err}"))?;
    let prefix = prefix_raw
        .parse::<u8>()
        .map_err(|err| format!("invalid CIDR prefix {prefix_raw:?}: {err}"))?;
    match ip {
        IpAddr::V4(ipv4) => {
            if prefix > 32 {
                return Err(format!("invalid IPv4 CIDR prefix: {prefix}"));
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(ipv4) & mask;
            Ok(ParsedCidr::V4 { network, prefix })
        }
        IpAddr::V6(ipv6) => {
            if prefix > 128 {
                return Err(format!("invalid IPv6 CIDR prefix: {prefix}"));
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = u128::from_be_bytes(ipv6.octets()) & mask;
            Ok(ParsedCidr::V6 { network, prefix })
        }
    }
}

fn canonicalize_ipv4_cidr(raw: &str, label: &str) -> Result<String, String> {
    let parsed = parse_cidr(raw).map_err(|err| format!("invalid {label}: {err}"))?;
    match parsed {
        ParsedCidr::V4 { network, prefix } => {
            if prefix == 32 {
                return Err(format!("{label} must not be an IPv4 host route"));
            }
            Ok(format!("{}/{}", Ipv4Addr::from(network), prefix))
        }
        ParsedCidr::V6 { .. } => Err(format!("{label} must be an IPv4 CIDR")),
    }
}

fn cidr_is_host_route(cidr: &ParsedCidr) -> bool {
    match cidr {
        ParsedCidr::V4 { prefix, .. } => *prefix == 32,
        ParsedCidr::V6 { prefix, .. } => *prefix == 128,
    }
}

fn is_peer_endpoint_key(key: &str) -> bool {
    if !key.starts_with("peer.") || !key.ends_with(".endpoint") {
        return false;
    }
    let Some(middle) = key.strip_prefix("peer.") else {
        return false;
    };
    let Some(index) = middle.strip_suffix(".endpoint") else {
        return false;
    };
    !index.is_empty() && index.chars().all(|ch| ch.is_ascii_digit())
}

fn split_endpoint_host_port(value: &str) -> Option<(&str, &str)> {
    let trimmed = value.trim();
    let (host, port) = trimmed.rsplit_once(':')?;
    if host.trim().is_empty() || port.trim().is_empty() {
        return None;
    }
    Some((host.trim(), port.trim()))
}

pub fn execute_ops_check_local_file_mode(
    config: CheckLocalFileModeConfig,
) -> Result<String, String> {
    let path = resolve_path(config.path.as_path())?;
    let metadata = fs::symlink_metadata(path.as_path())
        .map_err(|err| format!("stat failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("path must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() && !metadata.file_type().is_socket() {
        return Err(format!("path must be a regular file: {}", path.display()));
    }
    let mode = metadata.mode() & 0o777;
    let label = if config.label.trim().is_empty() {
        "file".to_string()
    } else {
        config.label.trim().to_string()
    };
    match parse_file_mode_policy(config.policy.as_str())? {
        FileModePolicy::OwnerOnly => {
            if mode & 0o077 != 0 {
                return Err(format!(
                    "{label} must be owner-only (0400/0600): {} ({mode:03o})",
                    path.display()
                ));
            }
        }
        FileModePolicy::NoGroupWorldWrite => {
            if mode & 0o022 != 0 {
                return Err(format!(
                    "{label} must not be group/world writable: {} ({mode:03o})",
                    path.display()
                ));
            }
        }
    }
    Ok(format!("{mode:03o}"))
}

pub fn execute_ops_redact_forensics_text() -> Result<String, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("read stdin failed: {err}"))?;
    Ok(redact_forensics_payload(input.as_str()))
}

pub fn execute_ops_write_cross_network_forensics_manifest(
    config: WriteCrossNetworkForensicsManifestConfig,
) -> Result<String, String> {
    let stage_dir = resolve_path(config.stage_dir.as_path())?;
    let output = resolve_path(config.output.as_path())?;
    if !stage_dir.is_dir() {
        return Err(format!(
            "stage-dir must be an existing directory: {}",
            stage_dir.display()
        ));
    }

    let mut node_dirs = fs::read_dir(stage_dir.as_path())
        .map_err(|err| format!("read stage-dir failed ({}): {err}", stage_dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .collect::<Vec<_>>();
    node_dirs.sort_by_key(|entry| entry.file_name());

    let mut nodes = Vec::new();
    for node_dir in node_dirs {
        let node_path = node_dir.path();
        let mut files = fs::read_dir(node_path.as_path())
            .map_err(|err| {
                format!(
                    "read node forensics directory failed ({}): {err}",
                    node_path.display()
                )
            })?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
            })
            .map(|entry| {
                fs::canonicalize(entry.path()).unwrap_or_else(|_| {
                    resolve_path(entry.path().as_path()).unwrap_or_else(|_| entry.path())
                })
            })
            .collect::<Vec<_>>();
        files.sort();
        nodes.push(json!({
            "label": node_dir.file_name().to_string_lossy().to_string(),
            "files": files.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        }));
    }

    let payload = json!({
        "schema_version": 1,
        "mode": "cross_network_failure_forensics",
        "stage": config.stage,
        "collected_at_utc": config.collected_at_utc,
        "bundle_dir": absolute_path_string(stage_dir.as_path())?,
        "nodes": nodes,
    });
    write_json_pretty(output.as_path(), &payload)?;
    Ok(output.display().to_string())
}

pub fn execute_ops_write_live_lab_stage_artifact_index(
    config: WriteLiveLabStageArtifactIndexConfig,
) -> Result<String, String> {
    let stage_name = config.stage_name.trim();
    if stage_name.is_empty() {
        return Err("stage-name is required".to_string());
    }

    let stage_dir = resolve_path(config.stage_dir.as_path())?;
    let output = resolve_path(config.output.as_path())?;
    if !stage_dir.is_dir() {
        return Err(format!(
            "stage-dir must be an existing directory: {}",
            stage_dir.display()
        ));
    }

    let mut files = Vec::new();
    walk_stage_files_recursive(
        stage_dir.as_path(),
        stage_dir.as_path(),
        Some(output.as_path()),
        &mut files,
    )?;

    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    for path in files {
        let metadata = fs::metadata(path.as_path())
            .map_err(|err| format!("stat failed ({}): {err}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!(
                "stage artifact must be a regular file: {}",
                path.display()
            ));
        }
        let relative_path = path
            .strip_prefix(stage_dir.as_path())
            .unwrap_or(path.as_path())
            .display()
            .to_string();
        let size_bytes = metadata.len();
        total_bytes = total_bytes.saturating_add(size_bytes);
        entries.push(json!({
            "relative_path": relative_path,
            "size_bytes": size_bytes,
            "sha256": sha256_hex_for_file(path.as_path())?,
        }));
    }

    let payload = json!({
        "schema_version": 1,
        "mode": "live_lab_stage_artifact_index",
        "stage_name": stage_name,
        "stage_dir": stage_dir.display().to_string(),
        "collected_at_utc": collected_at_utc_now(),
        "file_count": entries.len(),
        "total_bytes": total_bytes,
        "files": entries,
    });
    write_json_pretty(output.as_path(), &payload)?;
    Ok(output.display().to_string())
}

pub fn execute_ops_sha256_file(config: Sha256FileConfig) -> Result<String, String> {
    let path = resolve_path(config.path.as_path())?;
    let bytes = fs::read(path.as_path())
        .map_err(|err| format!("read file failed ({}): {err}", path.display()))?;
    let digest = Sha256::digest(bytes.as_slice());
    Ok(format!("{digest:x}"))
}

pub fn execute_ops_validate_cross_network_forensics_bundle(
    config: ValidateCrossNetworkForensicsBundleConfig,
) -> Result<String, String> {
    let stage_name = config.stage_name.trim();
    if stage_name.is_empty() {
        return Err("stage-name is required".to_string());
    }

    let nodes_tsv = resolve_path(config.nodes_tsv.as_path())?;
    let stage_dir = resolve_path(config.stage_dir.as_path())?;
    let output = resolve_path(config.output.as_path())?;
    if !stage_dir.is_dir() {
        return Err(format!(
            "stage-dir must be an existing directory: {}",
            stage_dir.display()
        ));
    }

    let rows = read_tsv_rows(nodes_tsv.as_path())?;
    if rows.is_empty() {
        return Err(format!(
            "nodes-tsv must contain at least one row: {}",
            nodes_tsv.display()
        ));
    }

    let required_stage_files = ["manifest.json", "route_matrix.txt", "cluster_snapshot.txt"];
    let mut missing_files = Vec::new();
    let mut empty_files = Vec::new();
    let mut invalid_files = Vec::new();
    let mut nodes = Vec::new();

    for file_name in required_stage_files {
        let path = stage_dir.join(file_name);
        if !path.exists() {
            missing_files.push(path.display().to_string());
            continue;
        }
        let metadata = fs::metadata(path.as_path())
            .map_err(|err| format!("stat failed ({}): {err}", path.display()))?;
        if metadata.len() == 0 {
            empty_files.push(path.display().to_string());
        }
    }

    let manifest_path = stage_dir.join("manifest.json");
    if manifest_path.exists() {
        let body = fs::read_to_string(manifest_path.as_path())
            .map_err(|err| format!("read JSON failed ({}): {err}", manifest_path.display()))?;
        if body.trim().is_empty() {
            empty_files.push(manifest_path.display().to_string());
        } else {
            match serde_json::from_str::<Value>(body.as_str()) {
                Ok(manifest) => {
                    let manifest_mode = manifest
                        .get("mode")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let manifest_stage = manifest
                        .get("stage")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let manifest_bundle_dir = manifest
                        .get("bundle_dir")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let manifest_nodes = manifest
                        .get("nodes")
                        .and_then(Value::as_array)
                        .map(|nodes| nodes.len())
                        .unwrap_or_default();
                    if manifest_mode != "cross_network_failure_forensics" {
                        invalid_files.push(format!(
                            "{}: unexpected mode {manifest_mode:?}",
                            manifest_path.display()
                        ));
                    }
                    if manifest_stage != stage_name {
                        invalid_files.push(format!(
                            "{}: unexpected stage {manifest_stage:?}",
                            manifest_path.display()
                        ));
                    }
                    if manifest_bundle_dir != stage_dir.display().to_string() {
                        invalid_files.push(format!(
                            "{}: unexpected bundle_dir {manifest_bundle_dir:?}",
                            manifest_path.display()
                        ));
                    }
                    if manifest_nodes != rows.len() {
                        invalid_files.push(format!(
                            "{}: manifest node count {manifest_nodes} does not match topology node count {}",
                            manifest_path.display(),
                            rows.len()
                        ));
                    }
                }
                Err(err) => {
                    invalid_files.push(format!(
                        "{}: parse JSON failed: {err}",
                        manifest_path.display()
                    ));
                }
            }
        }
    }

    for row in rows {
        if row.len() != 4 {
            return Err(format!(
                "nodes-tsv rows must contain 4 columns: {}",
                nodes_tsv.display()
            ));
        }

        let label = row[0].clone();
        let target = row[1].clone();
        let node_id = row[2].clone();
        let role = row[3].clone();
        let node_dir = stage_dir.join(label.as_str());
        let mut node_missing_files = Vec::new();
        let mut node_empty_files = Vec::new();

        for file_name in expected_forensics_node_files() {
            let path = node_dir.join(file_name);
            let relative_path = path
                .strip_prefix(stage_dir.as_path())
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            if !path.exists() {
                node_missing_files.push(relative_path.clone());
                missing_files.push(relative_path);
                continue;
            }
            let metadata = fs::metadata(path.as_path())
                .map_err(|err| format!("stat failed ({}): {err}", path.display()))?;
            if metadata.len() == 0 {
                node_empty_files.push(relative_path.clone());
                empty_files.push(relative_path);
            }
        }

        nodes.push(json!({
            "label": label,
            "target": target,
            "node_id": node_id,
            "role": role,
            "node_dir": node_dir.display().to_string(),
            "missing_files": node_missing_files,
            "empty_files": node_empty_files,
        }));
    }

    let bundle_status =
        if missing_files.is_empty() && empty_files.is_empty() && invalid_files.is_empty() {
            CHECK_PASS
        } else {
            CHECK_FAIL
        };
    let payload = json!({
        "schema_version": 1,
        "mode": "cross_network_forensics_bundle_validation",
        "stage_name": stage_name,
        "stage_dir": stage_dir.display().to_string(),
        "collected_at_utc": collected_at_utc_now(),
        "bundle_status": bundle_status,
        "node_count": nodes.len(),
        "required_stage_files": required_stage_files,
        "required_node_files": expected_forensics_node_files(),
        "missing_file_count": missing_files.len(),
        "empty_file_count": empty_files.len(),
        "invalid_file_count": invalid_files.len(),
        "missing_files": missing_files,
        "empty_files": empty_files,
        "invalid_files": invalid_files,
        "nodes": nodes,
    });
    write_json_pretty(output.as_path(), &payload)?;
    if bundle_status != CHECK_PASS {
        return Err("cross-network forensics bundle validation failed".to_string());
    }
    Ok(output.display().to_string())
}

pub fn execute_ops_write_cross_network_preflight_report(
    config: WriteCrossNetworkPreflightReportConfig,
) -> Result<String, String> {
    let nodes_tsv = resolve_path(config.nodes_tsv.as_path())?;
    let stage_dir = resolve_path(config.stage_dir.as_path())?;
    let output = resolve_path(config.output.as_path())?;
    let rows = read_tsv_rows(nodes_tsv.as_path())?;

    let mut nodes = Vec::new();
    for row in rows {
        if row.len() != 4 {
            continue;
        }
        let label = row[0].clone();
        let capability_file = stage_dir.join(format!("capabilities-{label}.txt"));
        nodes.push(json!({
            "label": row[0],
            "target": row[1],
            "node_id": row[2],
            "role": row[3],
            "capability_file": absolute_path_string(capability_file.as_path())?,
            "capability_file_exists": capability_file.exists(),
        }));
    }

    let payload = json!({
        "schema_version": 1,
        "mode": "cross_network_preflight",
        "reference_unix": config.reference_unix,
        "max_clock_skew_secs": config.max_clock_skew_secs,
        "discovery_max_age_secs": config.discovery_max_age_secs,
        "signed_artifact_max_age_secs": config.signed_artifact_max_age_secs,
        "nodes": nodes,
    });
    write_json_pretty(output.as_path(), &payload)?;
    Ok(output.display().to_string())
}

pub fn execute_ops_write_live_linux_reboot_recovery_report(
    config: WriteLiveLinuxRebootRecoveryReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let observations_path = resolve_path(config.observations_path.as_path())?;
    let exit_return = parse_pass_fail_skip(config.exit_return.as_str(), "--exit-return")?;
    let exit_boot_change =
        parse_pass_fail_skip(config.exit_boot_change.as_str(), "--exit-boot-change")?;
    let post_exit_dns_refresh = parse_pass_fail_skip(
        config.post_exit_dns_refresh.as_str(),
        "--post-exit-dns-refresh",
    )?;
    let post_exit_twohop =
        parse_pass_fail_skip(config.post_exit_twohop.as_str(), "--post-exit-twohop")?;
    let client_return = parse_pass_fail_skip(config.client_return.as_str(), "--client-return")?;
    let client_boot_change =
        parse_pass_fail_skip(config.client_boot_change.as_str(), "--client-boot-change")?;
    let post_client_dns_refresh = parse_pass_fail_skip(
        config.post_client_dns_refresh.as_str(),
        "--post-client-dns-refresh",
    )?;
    let post_client_twohop =
        parse_pass_fail_skip(config.post_client_twohop.as_str(), "--post-client-twohop")?;
    let salvage_twohop = parse_pass_fail_skip(config.salvage_twohop.as_str(), "--salvage-twohop")?;
    let observations = fs::read(observations_path.as_path())
        .map(|bytes| String::from_utf8_lossy(bytes.as_slice()).to_string())
        .unwrap_or_default();

    let checks = [
        ("exit_reboot_returns", exit_return),
        ("exit_boot_id_changes", exit_boot_change),
        (
            "post_exit_reboot_managed_dns_refresh",
            post_exit_dns_refresh,
        ),
        ("post_exit_reboot_twohop", post_exit_twohop),
        ("client_reboot_returns", client_return),
        ("client_boot_id_changes", client_boot_change),
        (
            "post_client_reboot_managed_dns_refresh",
            post_client_dns_refresh,
        ),
        ("post_client_reboot_twohop", post_client_twohop),
        ("client_failure_salvage_twohop", salvage_twohop),
    ];

    let relevant = checks
        .iter()
        .filter(|(_, value)| value.as_str() != CHECK_SKIPPED)
        .collect::<Vec<_>>();
    let status = if !relevant.is_empty()
        && relevant
            .iter()
            .all(|(_, value)| value.as_str() == CHECK_PASS)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };

    let mut failure_reasons = checks
        .iter()
        .filter_map(|(name, value)| {
            if value.as_str() == CHECK_FAIL {
                reboot_reason_for_check(name).map(ToString::to_string)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for line in observations
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        match line {
            "client_reboot_wait=fail" => {
                failure_reasons.push("client reboot wait timed out".to_string())
            }
            "exit_reboot_wait=fail" => {
                failure_reasons.push("exit reboot wait timed out".to_string())
            }
            "exit_post=" => {
                failure_reasons.push("exit post-reboot boot_id capture was empty".to_string())
            }
            "client_post=" => {
                failure_reasons.push("client post-reboot boot_id capture was empty".to_string())
            }
            _ => {}
        }
    }

    let checks_json = checks
        .iter()
        .map(|(name, value)| (name.to_string(), Value::String(value.clone())))
        .collect::<Map<_, _>>();
    let payload = json!({
        "schema_version": 1,
        "mode": "live_linux_reboot_recovery",
        "status": status,
        "checks": Value::Object(checks_json),
        "boot_ids": {
            "exit_pre": config.exit_pre,
            "exit_post": config.exit_post,
            "client_pre": config.client_pre,
            "client_post": config.client_post,
        },
        "failure_reasons": failure_reasons,
        "observations": observations.trim(),
    });

    write_json_pretty(report_path.as_path(), &payload)?;
    if status != CHECK_PASS {
        return Err("live_linux_reboot_recovery report status is fail".to_string());
    }
    Ok(report_path.display().to_string())
}

pub fn execute_ops_write_live_linux_lab_run_summary(
    config: WriteLiveLinuxLabRunSummaryConfig,
) -> Result<String, String> {
    let nodes_tsv = resolve_path(config.nodes_tsv.as_path())?;
    let stages_tsv = resolve_path(config.stages_tsv.as_path())?;
    let summary_json = resolve_path(config.summary_json.as_path())?;
    let summary_md = resolve_path(config.summary_md.as_path())?;
    let report_dir = resolve_path(Path::new(config.report_dir.as_str()))?;

    let node_rows = read_tsv_rows(nodes_tsv.as_path())?;
    let stage_rows = read_tsv_rows(stages_tsv.as_path())?;

    let nodes = node_rows
        .into_iter()
        .filter(|row| row.len() == 4)
        .map(|row| {
            json!({
                "label": row[0],
                "target": row[1],
                "node_id": row[2],
                "bootstrap_role": row[3],
            })
        })
        .collect::<Vec<_>>();

    let stages = stage_rows
        .into_iter()
        .filter(|row| row.len() == 8)
        .map(|row| {
            let stage_name = row[0].clone();
            let rc = row[3].parse::<i64>().unwrap_or(1);
            let worker_results =
                read_parallel_stage_results(report_dir.as_path(), stage_name.as_str());
            let failed_worker_count = worker_results
                .iter()
                .filter(|worker| worker.rc != 0)
                .count() as u64;
            let primary_failure_reason = worker_results
                .iter()
                .find(|worker| worker.rc != 0)
                .map(|worker| worker.primary_failure_reason.clone())
                .unwrap_or_default();
            json!({
                "stage": stage_name,
                "severity": row[1],
                "status": row[2],
                "rc": rc,
                "log_path": row[4],
                "message": row[5],
                "started_at": row[6],
                "finished_at": row[7],
                "failed_worker_count": failed_worker_count,
                "primary_failure_reason": primary_failure_reason,
                "worker_results": worker_results
                    .into_iter()
                    .map(|worker: LiveLabWorkerResult| {
                        json!({
                            "label": worker.label,
                            "target": worker.target,
                            "node_id": worker.node_id,
                            "role": worker.role,
                            "rc": worker.rc,
                            "started_at": worker.started_at,
                            "finished_at": worker.finished_at,
                            "log_path": worker.log_path,
                            "snapshot_path": worker.snapshot_path,
                            "route_policy_path": worker.route_policy_path,
                            "dns_state_path": worker.dns_state_path,
                            "primary_failure_reason": worker.primary_failure_reason,
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "schema_version": 1,
        "run_id": config.run_id,
        "network_id": config.network_id,
        "report_dir": report_dir.display().to_string(),
        "overall_status": config.overall_status,
        "started_at_local": config.started_at_local,
        "started_at_utc": config.started_at_utc,
        "started_at_unix": config.started_at_unix,
        "finished_at_local": config.finished_at_local,
        "finished_at_utc": config.finished_at_utc,
        "finished_at_unix": config.finished_at_unix,
        "elapsed_secs": config.elapsed_secs,
        "elapsed_human": config.elapsed_human,
        "nodes": nodes,
        "stages": stages,
    });
    write_json_pretty(summary_json.as_path(), &payload)?;

    let mut lines = Vec::new();
    lines.push(format!(
        "# Live Linux Lab Orchestrator Summary ({})",
        payload
            .get("run_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(String::new());
    lines.push(format!(
        "- overall_status: `{}`",
        payload
            .get("overall_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- network_id: `{}`",
        payload
            .get("network_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- report_dir: `{}`",
        payload
            .get("report_dir")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- started_at_local: `{}`",
        payload
            .get("started_at_local")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- started_at_utc: `{}`",
        payload
            .get("started_at_utc")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- finished_at_local: `{}`",
        payload
            .get("finished_at_local")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- finished_at_utc: `{}`",
        payload
            .get("finished_at_utc")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!(
        "- elapsed: `{}`",
        payload
            .get("elapsed_human")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(String::new());
    lines.push("## Nodes".to_string());
    lines.push(String::new());
    if let Some(node_array) = payload.get("nodes").and_then(Value::as_array) {
        for node in node_array {
            lines.push(format!(
                "- `{}`: `{}` (`{}`, bootstrap role `{}`)",
                node.get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                node.get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                node.get("node_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                node.get("bootstrap_role")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ));
        }
    }
    lines.push(String::new());
    lines.push("## Stages".to_string());
    lines.push(String::new());
    if let Some(stage_array) = payload.get("stages").and_then(Value::as_array) {
        for stage in stage_array {
            lines.push(format!(
                "- `{}` [{}] -> `{}` (rc={})",
                stage
                    .get("stage")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                stage
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                stage
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                stage.get("rc").and_then(Value::as_i64).unwrap_or(1),
            ));
            lines.push(format!(
                "  log: `{}`",
                stage
                    .get("log_path")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
            lines.push(format!(
                "  detail: {}",
                stage
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("stage detail unavailable")
            ));
            if let Some(worker_results) = stage.get("worker_results").and_then(Value::as_array)
                && !worker_results.is_empty()
            {
                lines.push(format!(
                    "  workers: {}/{} failed",
                    stage
                        .get("failed_worker_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    worker_results.len()
                ));
                if let Some(first_failed) = worker_results
                    .iter()
                    .find(|worker| worker.get("rc").and_then(Value::as_i64).unwrap_or(0) != 0)
                {
                    lines.push(format!(
                        "  first_failed_node: `{}` reason={}",
                        first_failed
                            .get("label")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        first_failed
                            .get("primary_failure_reason")
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                            .unwrap_or("see worker log")
                    ));
                    if let Some(snapshot_path) = first_failed
                        .get("snapshot_path")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    {
                        lines.push(format!("  snapshot: `{snapshot_path}`"));
                    }
                }
            }
        }
    }
    ensure_parent_dir(summary_md.as_path())?;
    fs::write(summary_md.as_path(), lines.join("\n") + "\n").map_err(|err| {
        format!(
            "write markdown summary failed ({}): {err}",
            summary_md.display()
        )
    })?;

    Ok(format!(
        "live lab run summary generated: json={} md={}",
        summary_json.display(),
        summary_md.display()
    ))
}

pub fn execute_ops_scan_ipv4_port_range(config: ScanIpv4PortRangeConfig) -> Result<String, String> {
    if config.start_host == 0 {
        return Err("--start-host must be between 1 and 254".to_string());
    }
    if config.end_host == 0 {
        return Err("--end-host must be between 1 and 254".to_string());
    }
    if config.start_host > config.end_host {
        return Err("--start-host must be <= --end-host".to_string());
    }
    let prefix = parse_network_prefix(config.network_prefix.as_str())?;
    let timeout = Duration::from_millis(config.timeout_ms.max(1));
    let output_key = if config.output_key.trim().is_empty() {
        "hosts=".to_string()
    } else {
        config.output_key
    };
    let mut hits = Vec::new();
    for host in config.start_host..=config.end_host {
        let ip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], host);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, config.port));
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            hits.push(ip.to_string());
        }
    }
    Ok(format!("{output_key}{}", hits.join(",")))
}

pub fn execute_ops_update_role_switch_host_result(
    config: UpdateRoleSwitchHostResultConfig,
) -> Result<String, String> {
    let hosts_json_path = resolve_path(config.hosts_json_path.as_path())?;
    let os_id = config.os_id.trim();
    if os_id.is_empty() {
        return Err("--os-id must be non-empty".to_string());
    }
    let temp_role = config.temp_role.trim();
    if temp_role.is_empty() {
        return Err("--temp-role must be non-empty".to_string());
    }
    let switch_execution = parse_pass_fail(config.switch_execution.as_str(), "switch-execution")?;
    let post_switch_reconcile = parse_pass_fail(
        config.post_switch_reconcile.as_str(),
        "post-switch-reconcile",
    )?;
    let policy_still_enforced = parse_pass_fail(
        config.policy_still_enforced.as_str(),
        "policy-still-enforced",
    )?;
    let least_privilege_preserved = parse_pass_fail(
        config.least_privilege_preserved.as_str(),
        "least-privilege-preserved",
    )?;

    let mut payload = read_json_object_or_empty(hosts_json_path.as_path())?;
    payload.insert(
        os_id.to_string(),
        json!({
            "transition": {
                "from_role": "client",
                "to_role": temp_role,
                "status": if switch_execution == CHECK_PASS { CHECK_PASS } else { CHECK_FAIL },
            },
            "checks": {
                "switch_execution": switch_execution,
                "post_switch_reconcile": post_switch_reconcile,
                "policy_still_enforced": policy_still_enforced,
                "least_privilege_preserved": least_privilege_preserved,
            },
        }),
    );
    write_json_pretty(hosts_json_path.as_path(), &Value::Object(payload))?;
    Ok(hosts_json_path.display().to_string())
}

pub fn execute_ops_write_role_switch_matrix_report(
    config: WriteRoleSwitchMatrixReportConfig,
) -> Result<String, String> {
    let hosts_json_path = resolve_path(config.hosts_json_path.as_path())?;
    let report_path = resolve_path(config.report_path.as_path())?;
    let source_path = resolve_path(config.source_path.as_path())?;
    let git_commit = config.git_commit.trim().to_ascii_lowercase();
    if git_commit.is_empty() {
        return Err("--git-commit must be non-empty".to_string());
    }
    let overall_status = config.overall_status.trim();
    if overall_status != CHECK_PASS && overall_status != CHECK_FAIL {
        return Err(format!(
            "--overall-status must be pass or fail (got: {:?})",
            config.overall_status
        ));
    }
    let hosts = read_json_object_or_empty(hosts_json_path.as_path())?;
    let report = json!({
        "schema_version": 1,
        "evidence_mode": "measured",
        "git_commit": git_commit,
        "captured_at_unix": config.captured_at_unix,
        "status": overall_status,
        "hosts": Value::Object(hosts),
        "source_artifact": source_path.display().to_string(),
    });
    write_json_pretty(report_path.as_path(), &report)?;
    Ok(report_path.display().to_string())
}

pub fn execute_ops_write_live_linux_server_ip_bypass_report(
    config: WriteLiveLinuxServerIpBypassReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let probe_ip = config
        .probe_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("invalid probe IP {:?}: {err}", config.probe_ip))?;
    let probe_from_client_status = parse_pass_fail(
        config.probe_from_client_status.as_str(),
        "probe-from-client-status",
    )?;
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let mut allowed_networks = Vec::new();
    for part in config
        .allowed_management_cidrs
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        allowed_networks.push((part.to_string(), parse_cidr(part)?));
    }

    let internet_route_ok = config.client_internet_route.contains("dev rustynet0");
    let probe_route_direct = !config.client_probe_route.contains("dev rustynet0")
        && config
            .client_probe_route
            .contains(probe_ip.to_string().as_str());
    let probe_host_self_reachable = config.probe_self_test.contains("probe-ok");

    let mut unexpected_bypass_routes = Vec::new();
    for raw_line in config.client_table_51820.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.contains("dev rustynet0") || line.starts_with("default ") {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        let parsed = match parse_cidr(first) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if cidr_is_host_route(&parsed) {
            continue;
        }
        let allowed = allowed_networks
            .iter()
            .any(|(_, allowed)| *allowed == parsed);
        if !allowed {
            unexpected_bypass_routes.push(line.to_string());
        }
    }

    let checks = json!({
        "internet_route_via_rustynet0": if internet_route_ok { CHECK_PASS } else { CHECK_FAIL },
        "probe_host_self_service_reachable": if probe_host_self_reachable { CHECK_PASS } else { CHECK_FAIL },
        "probe_endpoint_route_direct_not_tunnelled": if probe_route_direct { CHECK_PASS } else { CHECK_FAIL },
        "probe_service_blocked_from_client": probe_from_client_status,
        "no_unexpected_bypass_routes": if unexpected_bypass_routes.is_empty() { CHECK_PASS } else { CHECK_FAIL },
    });

    let overall = if checks
        .as_object()
        .map(|items| items.values().all(|v| v.as_str() == Some(CHECK_PASS)))
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };

    let payload = json!({
        "phase": "phase10",
        "mode": "live_linux_server_ip_bypass",
        "evidence_mode": "measured",
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": overall,
        "probe_host_ip": probe_ip.to_string(),
        "probe_port": config.probe_port,
        "checks": checks,
        "evidence": {
            "client_internet_route": config.client_internet_route,
            "client_probe_route": config.client_probe_route,
            "client_table_51820": config.client_table_51820,
            "client_endpoints": config.client_endpoints,
            "probe_self_test": config.probe_self_test,
            "client_probe_output": config.probe_from_client_output,
            "unexpected_bypass_routes": unexpected_bypass_routes,
            "allowed_management_cidrs": allowed_networks.into_iter().map(|(raw, _)| raw).collect::<Vec<_>>(),
        }
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_write_live_linux_control_surface_report(
    config: WriteLiveLinuxControlSurfaceReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let work_dir = resolve_path(config.work_dir.as_path())?;
    if !work_dir.is_dir() {
        return Err(format!(
            "work-dir must be an existing directory: {}",
            work_dir.display()
        ));
    }
    if config.host_labels.is_empty() {
        return Err("at least one --host-label is required".to_string());
    }

    let Some((dns_host, dns_port)) = config.dns_bind_addr.rsplit_once(':') else {
        return Err(format!(
            "invalid --dns-bind-addr {:?}; expected host:port",
            config.dns_bind_addr
        ));
    };
    let dns_port_num = dns_port
        .parse::<u16>()
        .map_err(|err| format!("invalid dns bind port {dns_port:?}: {err}"))?;
    if dns_host.trim().is_empty() {
        return Err("dns bind host must not be empty".to_string());
    }
    let allowed_udp = format!("{}:{}", dns_host.trim(), dns_port_num);
    let remote_dns_probe_status = parse_pass_fail_skip(
        config.remote_dns_probe_status.as_str(),
        "remote-dns-probe-status",
    )?;
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let mut host_results = Map::new();
    let mut overall = CHECK_PASS.to_string();
    for label in &config.host_labels {
        let daemon_meta = fs::read_to_string(work_dir.join(format!("{label}.daemon_socket.txt")))
            .map_err(|err| format!("read {label} daemon metadata failed: {err}"))?;
        let helper_meta = fs::read_to_string(work_dir.join(format!("{label}.helper_socket.txt")))
            .map_err(|err| format!("read {label} helper metadata failed: {err}"))?;
        let listeners_raw =
            fs::read_to_string(work_dir.join(format!("{label}.inet_listeners.txt")))
                .map_err(|err| format!("read {label} listener capture failed: {err}"))?;
        let dns_service_state =
            fs::read_to_string(work_dir.join(format!("{label}.managed_dns_state.txt")))
                .map_err(|err| format!("read {label} DNS service state failed: {err}"))?;

        let daemon_meta_trimmed = daemon_meta.trim().to_string();
        let helper_meta_trimmed = helper_meta.trim().to_string();
        let daemon_parts = daemon_meta_trimmed.split('|').collect::<Vec<_>>();
        let helper_parts = helper_meta_trimmed.split('|').collect::<Vec<_>>();
        let daemon_owner = daemon_parts.get(2).copied().unwrap_or_default();
        let daemon_group = daemon_parts.get(3).copied().unwrap_or_default();
        let daemon_owner_ok = daemon_owner == "root" || daemon_owner == "rustynetd";
        let daemon_ok = daemon_parts.len() == 4
            && daemon_parts[0] == "socket"
            && daemon_parts[1] == "600"
            && daemon_owner_ok
            && daemon_group == daemon_owner;
        let helper_ok = helper_parts.len() == 4
            && helper_parts[0] == "socket"
            && helper_parts[1] == "660"
            && helper_parts[2] == "root";

        let mut tcp_listener_ok = true;
        let mut udp_listener_ok = true;
        let mut rustynet_listener_lines = Vec::new();
        for line in listeners_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if !line.contains("rustynetd") {
                continue;
            }
            rustynet_listener_lines.push(line.to_string());
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 5 {
                tcp_listener_ok = false;
                udp_listener_ok = false;
                continue;
            }
            let proto = parts[0];
            let local_addr = parts[4];
            if proto.starts_with("tcp") {
                tcp_listener_ok = false;
            } else if proto.starts_with("udp") {
                if local_addr != allowed_udp {
                    udp_listener_ok = false;
                }
            } else {
                udp_listener_ok = false;
            }
        }

        if !daemon_ok || !helper_ok || !tcp_listener_ok || !udp_listener_ok {
            overall = CHECK_FAIL.to_string();
        }

        host_results.insert(
            label.to_string(),
            json!({
                "checks": {
                    "daemon_socket_secure": if daemon_ok { CHECK_PASS } else { CHECK_FAIL },
                    "helper_socket_secure": if helper_ok { CHECK_PASS } else { CHECK_FAIL },
                    "no_rustynet_tcp_listener": if tcp_listener_ok { CHECK_PASS } else { CHECK_FAIL },
                    "rustynet_udp_loopback_only": if udp_listener_ok { CHECK_PASS } else { CHECK_FAIL },
                },
                "evidence": {
                    "daemon_socket_meta": daemon_meta_trimmed,
                    "helper_socket_meta": helper_meta_trimmed,
                    "managed_dns_service_state": dns_service_state.trim(),
                    "rustynet_listener_lines": rustynet_listener_lines,
                }
            }),
        );
    }

    if remote_dns_probe_status == CHECK_FAIL {
        overall = CHECK_FAIL.to_string();
    }

    let all_daemon_ok = host_results.values().all(|value| {
        value
            .get("checks")
            .and_then(|checks| checks.get("daemon_socket_secure"))
            .and_then(Value::as_str)
            == Some(CHECK_PASS)
    });
    let all_helper_ok = host_results.values().all(|value| {
        value
            .get("checks")
            .and_then(|checks| checks.get("helper_socket_secure"))
            .and_then(Value::as_str)
            == Some(CHECK_PASS)
    });
    let all_no_tcp = host_results.values().all(|value| {
        value
            .get("checks")
            .and_then(|checks| checks.get("no_rustynet_tcp_listener"))
            .and_then(Value::as_str)
            == Some(CHECK_PASS)
    });
    let all_udp_loopback = host_results.values().all(|value| {
        value
            .get("checks")
            .and_then(|checks| checks.get("rustynet_udp_loopback_only"))
            .and_then(Value::as_str)
            == Some(CHECK_PASS)
    });

    let payload = json!({
        "phase": "phase10",
        "mode": "live_linux_control_surface_exposure",
        "evidence_mode": "measured",
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": overall,
        "dns_bind_addr": config.dns_bind_addr,
        "checks": {
            "all_daemon_sockets_secure": if all_daemon_ok { CHECK_PASS } else { CHECK_FAIL },
            "all_helper_sockets_secure": if all_helper_ok { CHECK_PASS } else { CHECK_FAIL },
            "no_rustynet_tcp_listeners": if all_no_tcp { CHECK_PASS } else { CHECK_FAIL },
            "rustynet_udp_loopback_only": if all_udp_loopback { CHECK_PASS } else { CHECK_FAIL },
            "remote_underlay_dns_probe_blocked": remote_dns_probe_status,
        },
        "hosts": Value::Object(host_results),
        "evidence": {
            "remote_underlay_dns_probe_output": config.remote_dns_probe_output,
        },
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_rewrite_assignment_peer_endpoint_ip(
    config: RewriteAssignmentPeerEndpointIpConfig,
) -> Result<String, String> {
    let assignment_path = resolve_path(config.assignment_path.as_path())?;
    let endpoint_ip = config
        .endpoint_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| {
            format!(
                "invalid endpoint IPv4 address {:?}: {err}",
                config.endpoint_ip
            )
        })?
        .to_string();
    let metadata = fs::symlink_metadata(assignment_path.as_path()).map_err(|err| {
        format!(
            "stat assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "assignment path must not be a symlink: {}",
            assignment_path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "assignment path must be a regular file: {}",
            assignment_path.display()
        ));
    }

    let body = fs::read_to_string(assignment_path.as_path()).map_err(|err| {
        format!(
            "read assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    let mut replaced = 0usize;
    let mut updated = Vec::new();
    for line in body.lines() {
        let mut line_out = line.to_string();
        if let Some((key, value)) = line.split_once('=')
            && is_peer_endpoint_key(key.trim())
        {
            let (_, port) = split_endpoint_host_port(value).ok_or_else(|| {
                format!(
                    "invalid peer endpoint value {:?} in {}",
                    value.trim(),
                    assignment_path.display()
                )
            })?;
            let port_num = port.parse::<u16>().map_err(|err| {
                format!(
                    "invalid endpoint port {:?} in {}: {err}",
                    port,
                    assignment_path.display()
                )
            })?;
            line_out = format!("{}={endpoint_ip}:{port_num}", key.trim());
            replaced += 1;
        }
        updated.push(line_out);
    }
    if replaced == 0 {
        return Err(format!(
            "failed to locate peer endpoint fields in assignment bundle ({})",
            assignment_path.display()
        ));
    }
    fs::write(
        assignment_path.as_path(),
        format!("{}\n", updated.join("\n")),
    )
    .map_err(|err| {
        format!(
            "write assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    Ok(replaced.to_string())
}

pub fn execute_ops_rewrite_assignment_mesh_cidr(
    config: RewriteAssignmentMeshCidrConfig,
) -> Result<String, String> {
    let assignment_path = resolve_path(config.assignment_path.as_path())?;
    let mesh_cidr = canonicalize_ipv4_cidr(config.mesh_cidr.as_str(), "mesh CIDR")?;
    let metadata = fs::symlink_metadata(assignment_path.as_path()).map_err(|err| {
        format!(
            "stat assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "assignment path must not be a symlink: {}",
            assignment_path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "assignment path must be a regular file: {}",
            assignment_path.display()
        ));
    }

    let body = fs::read_to_string(assignment_path.as_path()).map_err(|err| {
        format!(
            "read assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    let mut rewritten = false;
    let mut updated = Vec::new();
    for line in body.lines() {
        let mut line_out = line.to_string();
        if let Some((key, _value)) = line.split_once('=')
            && key.trim() == "mesh_cidr"
        {
            line_out = format!("mesh_cidr={mesh_cidr}");
            rewritten = true;
        }
        updated.push(line_out);
    }
    if !rewritten {
        return Err(format!(
            "failed to locate mesh_cidr field in assignment bundle ({})",
            assignment_path.display()
        ));
    }
    fs::write(
        assignment_path.as_path(),
        format!("{}\n", updated.join("\n")),
    )
    .map_err(|err| {
        format!(
            "write assignment path failed ({}): {err}",
            assignment_path.display()
        )
    })?;
    Ok(mesh_cidr)
}

pub fn execute_ops_write_live_linux_endpoint_hijack_report(
    config: WriteLiveLinuxEndpointHijackReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let rogue_endpoint_ip = config
        .rogue_endpoint_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| {
            format!(
                "invalid rogue endpoint IPv4 address {:?}: {err}",
                config.rogue_endpoint_ip
            )
        })?
        .to_string();
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let checks = json!({
        "baseline_runtime_secure": if !config.baseline_status.contains("state=FailClosed") { CHECK_PASS } else { CHECK_FAIL },
        "hijack_drives_fail_closed": if config.status_after_hijack.contains("state=FailClosed") { CHECK_PASS } else { CHECK_FAIL },
        "restricted_safe_mode_engaged": if config.status_after_hijack.contains("restricted_safe_mode=true") { CHECK_PASS } else { CHECK_FAIL },
        "netcheck_reports_fail_closed": if config.netcheck_after_hijack.contains("path_mode=fail_closed") { CHECK_PASS } else { CHECK_FAIL },
        "rogue_endpoint_not_adopted": if !config.endpoints_after_hijack.contains(rogue_endpoint_ip.as_str()) { CHECK_PASS } else { CHECK_FAIL },
        "recovery_restores_secure_runtime": if !config.status_after_recovery.contains("state=FailClosed")
            && config.status_after_recovery.contains("restricted_safe_mode=false")
        {
            CHECK_PASS
        } else {
            CHECK_FAIL
        },
        "recovery_keeps_rogue_endpoint_rejected": if !config.endpoints_after_recovery.contains(rogue_endpoint_ip.as_str()) { CHECK_PASS } else { CHECK_FAIL },
    });
    let status = if checks
        .as_object()
        .map(|items| {
            items
                .values()
                .all(|value| value.as_str() == Some(CHECK_PASS))
        })
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };
    let payload = json!({
        "phase": "phase10",
        "mode": "live_linux_endpoint_hijack",
        "evidence_mode": "measured",
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": status,
        "rogue_endpoint_ip": rogue_endpoint_ip,
        "checks": checks,
        "evidence": {
            "baseline_status": config.baseline_status,
            "baseline_netcheck": config.baseline_netcheck,
            "baseline_endpoints": config.baseline_endpoints,
            "status_after_hijack": config.status_after_hijack,
            "netcheck_after_hijack": config.netcheck_after_hijack,
            "endpoints_after_hijack": config.endpoints_after_hijack,
            "status_after_recovery": config.status_after_recovery,
            "endpoints_after_recovery": config.endpoints_after_recovery,
        },
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_write_real_wireguard_exitnode_e2e_report(
    config: WriteRealWireguardExitnodeE2eReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let exit_status = parse_pass_fail(config.exit_status.as_str(), "--exit-status")?;
    let lan_off_status = parse_pass_fail(config.lan_off_status.as_str(), "--lan-off-status")?;
    let lan_on_status = parse_pass_fail(config.lan_on_status.as_str(), "--lan-on-status")?;
    let dns_up_status = parse_pass_fail(config.dns_up_status.as_str(), "--dns-up-status")?;
    let kill_switch_status =
        parse_pass_fail(config.kill_switch_status.as_str(), "--kill-switch-status")?;
    let dns_down_status = parse_pass_fail(config.dns_down_status.as_str(), "--dns-down-status")?;
    let environment = if config.environment.trim().is_empty() {
        "lab-netns".to_string()
    } else {
        config.environment.trim().to_string()
    };
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let checks = json!({
        "exit_node_routing": exit_status,
        "lan_toggle_off_blocks": lan_off_status,
        "lan_toggle_on_allows": lan_on_status,
        "dns_reaches_protected_path_when_tunnel_up": dns_up_status,
        "kill_switch_blocks_egress_when_tunnel_down": kill_switch_status,
        "dns_fail_close_when_tunnel_down": dns_down_status,
    });
    let status = if checks
        .as_object()
        .map(|items| {
            items
                .values()
                .all(|value| value.as_str() == Some(CHECK_PASS))
        })
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };
    let payload = json!({
        "phase": "phase10",
        "mode": "real_netns_wireguard",
        "evidence_mode": "measured",
        "environment": environment,
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": status,
        "checks": checks,
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_write_real_wireguard_no_leak_under_load_report(
    config: WriteRealWireguardNoLeakUnderLoadReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let load_pcap = resolve_path(config.load_pcap.as_path())?;
    let down_pcap = resolve_path(config.down_pcap.as_path())?;
    let tunnel_up_status = parse_pass_fail(config.tunnel_up_status.as_str(), "--tunnel-up-status")?;
    let load_ping_status = parse_pass_fail(config.load_ping_status.as_str(), "--load-ping-status")?;
    let tunnel_down_block_status = parse_pass_fail(
        config.tunnel_down_block_status.as_str(),
        "--tunnel-down-block-status",
    )?;
    let environment = if config.environment.trim().is_empty() {
        "lab-netns".to_string()
    } else {
        config.environment.trim().to_string()
    };
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let load_lines = decode_tcpdump_lines(load_pcap.as_path())?;
    let down_lines = decode_tcpdump_lines(down_pcap.as_path())?;
    let load_tunnel_packets = count_no_leak_tunnel_packets(&load_lines);
    let load_cleartext_packets = count_no_leak_cleartext_packets(&load_lines);
    let down_cleartext_packets = count_no_leak_cleartext_packets(&down_lines);

    let checks = json!({
        "tunnel_up_connectivity": tunnel_up_status,
        "load_ping_success": load_ping_status,
        "tunnel_transport_observed_under_load": if load_tunnel_packets > 0 { CHECK_PASS } else { CHECK_FAIL },
        "no_underlay_cleartext_during_load": if load_cleartext_packets == 0 { CHECK_PASS } else { CHECK_FAIL },
        "tunnel_down_fail_closed": tunnel_down_block_status,
        "no_underlay_cleartext_after_tunnel_down": if down_cleartext_packets == 0 { CHECK_PASS } else { CHECK_FAIL },
    });
    let status = if checks
        .as_object()
        .map(|items| {
            items
                .values()
                .all(|value| value.as_str() == Some(CHECK_PASS))
        })
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };
    let payload = json!({
        "phase": "phase10",
        "mode": "real_netns_no_leak_under_load",
        "evidence_mode": "measured",
        "environment": environment,
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": status,
        "checks": checks,
        "metrics": {
            "load_tunnel_packets": load_tunnel_packets,
            "load_cleartext_packets": load_cleartext_packets,
            "down_cleartext_packets": down_cleartext_packets,
        },
        "source_artifacts": [
            load_pcap.display().to_string(),
            down_pcap.display().to_string()
        ],
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_verify_no_leak_dataplane_report(
    config: VerifyNoLeakDataplaneReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let body = fs::read_to_string(report_path.as_path())
        .map_err(|err| format!("missing no-leak report: {} ({err})", report_path.display()))?;
    let payload = serde_json::from_str::<Value>(body.as_str()).map_err(|err| {
        format!(
            "invalid no-leak report JSON ({}): {err}",
            report_path.display()
        )
    })?;
    let object = payload
        .as_object()
        .ok_or_else(|| "no-leak dataplane report must be a JSON object".to_string())?;
    is_plaintext_no_leak_report(object)?;
    Ok("No-leak dataplane gate: PASS".to_string())
}

pub fn execute_ops_e2e_dns_query(config: E2eDnsQueryConfig) -> Result<String, String> {
    let server = config
        .server
        .trim()
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid --server value {:?}: {err}", config.server))?;
    let qname = validate_dns_qname(config.qname.as_str())?;
    let timeout_ms = if config.timeout_ms == 0 {
        1000
    } else {
        config.timeout_ms.min(60_000)
    };
    let socket = UdpSocket::bind(dns_query_bind_addr(server))
        .map_err(|err| format!("bind UDP socket failed: {err}"))?;
    let timeout = Duration::from_millis(timeout_ms);
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("set UDP read timeout failed: {err}"))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("set UDP write timeout failed: {err}"))?;

    let packet = build_dns_query_packet(qname.as_str());
    let server_addr = SocketAddr::new(server, config.port);
    let mut result = json!({
        "rcode": -1,
        "answer_count": 0,
        "answer_ip": "",
        "answer_ttl": 0,
        "error": "",
    });

    let query_outcome = (|| -> Result<(), String> {
        socket
            .send_to(packet.as_slice(), server_addr)
            .map_err(|err| format!("dns query send failed: {err}"))?;
        let mut response = [0u8; 512];
        let (size, _) = socket
            .recv_from(&mut response)
            .map_err(|err| format!("dns query receive failed: {err}"))?;
        if size < 12 {
            return Err("dns response too short".to_string());
        }
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = (flags & 0x000F) as i64;
        let answer_count = u16::from_be_bytes([response[6], response[7]]) as u64;
        let (rcode, answer_count, answer_ip, answer_ttl) =
            decode_first_dns_answer(&response[..size], rcode, answer_count)?;
        result["rcode"] = Value::from(rcode);
        result["answer_count"] = Value::from(answer_count);
        result["answer_ip"] = Value::from(answer_ip);
        result["answer_ttl"] = Value::from(answer_ttl);
        Ok(())
    })();

    if let Err(err) = query_outcome {
        result["error"] = Value::from(err);
    }
    let output =
        serde_json::to_string(&result).map_err(|err| format!("serialize JSON failed: {err}"))?;
    if config.fail_on_no_response
        && result
            .get("error")
            .and_then(Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
    {
        return Err(result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("dns query failed")
            .to_string());
    }
    Ok(output)
}

fn dns_query_bind_addr(server: IpAddr) -> SocketAddr {
    match server {
        IpAddr::V4(addr) if addr.is_loopback() => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        }
        IpAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(addr) if addr.is_loopback() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
        }
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

pub fn execute_ops_e2e_http_probe_server(
    config: E2eHttpProbeServerConfig,
) -> Result<String, String> {
    let bind_ip = config
        .bind_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("invalid --bind-ip value {:?}: {err}", config.bind_ip))?;
    let response_body = if config.response_body.is_empty() {
        "probe-ok".to_string()
    } else {
        config.response_body
    };
    let listener = TcpListener::bind(SocketAddrV4::new(bind_ip, config.port))
        .map_err(|err| format!("bind HTTP probe server failed: {err}"))?;
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(value) => value,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let mut request_buf = [0u8; 1024];
        let _ = stream.read(&mut request_buf);
        let body = response_body.as_bytes();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if stream.write_all(header.as_bytes()).is_err() {
            continue;
        }
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
    Err("HTTP probe server listener terminated unexpectedly".to_string())
}

pub fn execute_ops_e2e_http_probe_client(
    config: E2eHttpProbeClientConfig,
) -> Result<String, String> {
    let host = config
        .host
        .trim()
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid --host value {:?}: {err}", config.host))?;
    let timeout_ms = if config.timeout_ms == 0 {
        2000
    } else {
        config.timeout_ms.min(60_000)
    };
    let timeout = Duration::from_millis(timeout_ms);
    let target = SocketAddr::new(host, config.port);
    let mut stream = TcpStream::connect_timeout(&target, timeout)
        .map_err(|err| format!("TCP connect failed: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("set TCP read timeout failed: {err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("set TCP write timeout failed: {err}"))?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
        .map_err(|err| format!("TCP probe write failed: {err}"))?;
    let mut response = vec![0u8; 4096];
    let read_size = stream
        .read(response.as_mut_slice())
        .map_err(|err| format!("TCP probe read failed: {err}"))?;
    let response_text = String::from_utf8_lossy(&response[..read_size]).to_string();
    if !response_text.contains(config.expect_marker.as_str()) {
        return Err("probe marker missing from response".to_string());
    }
    Ok(config.expect_marker)
}

pub fn execute_ops_read_json_field(config: ReadJsonFieldConfig) -> Result<String, String> {
    let payload = serde_json::from_str::<Value>(config.payload.as_str())
        .map_err(|err| format!("parse --payload JSON failed: {err}"))?;
    let object = payload
        .as_object()
        .ok_or_else(|| "--payload must be a JSON object".to_string())?;
    let value = object.get(config.field.as_str());
    match value {
        None => Ok(String::new()),
        Some(Value::Null) => Ok(String::new()),
        Some(Value::Bool(flag)) => {
            if *flag {
                Ok("true".to_string())
            } else {
                Ok("false".to_string())
            }
        }
        Some(Value::String(text)) => Ok(text.clone()),
        Some(Value::Number(number)) => Ok(number.to_string()),
        Some(other) => {
            serde_json::to_string(other).map_err(|err| format!("serialize field failed: {err}"))
        }
    }
}

pub fn execute_ops_extract_managed_dns_expected_ip(
    config: ExtractManagedDnsExpectedIpConfig,
) -> Result<String, String> {
    let fqdn = config.fqdn.trim().to_string();
    if fqdn.is_empty() {
        return Err("--fqdn must be non-empty".to_string());
    }
    let fqdn_token = format!("fqdn={fqdn}");
    for line in config.inspect_output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.contains(&fqdn_token.as_str()) {
            for token in &tokens {
                if let Some(value) = token.strip_prefix("expected_ip=") {
                    return Ok(value.to_string());
                }
            }
        }

        for (index, token) in tokens.iter().enumerate() {
            let Some(record_token) = token.strip_prefix("record.") else {
                continue;
            };
            let Some((record_index, token_fqdn)) = record_token.split_once(".fqdn=") else {
                continue;
            };
            if token_fqdn != fqdn {
                continue;
            }

            let expected_ip_prefix = format!("record.{record_index}.expected_ip=");
            for candidate in &tokens {
                if let Some(value) = candidate.strip_prefix(expected_ip_prefix.as_str()) {
                    return Ok(value.to_string());
                }
            }

            for candidate in tokens.iter().skip(index + 1) {
                if let Some(value) = candidate.strip_prefix("expected_ip=") {
                    return Ok(value.to_string());
                }
            }
        }
    }
    Ok(String::new())
}

pub fn execute_ops_write_active_network_signed_state_tamper_report(
    config: WriteActiveNetworkSignedStateTamperReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let baseline_status = parse_pass_fail(config.baseline_status.as_str(), "--baseline-status")?;
    let tamper_reject_status = parse_pass_fail(
        config.tamper_reject_status.as_str(),
        "--tamper-reject-status",
    )?;
    let fail_closed_status =
        parse_pass_fail(config.fail_closed_status.as_str(), "--fail-closed-status")?;
    let netcheck_fail_closed_status = parse_pass_fail(
        config.netcheck_fail_closed_status.as_str(),
        "--netcheck-fail-closed-status",
    )?;
    let recovery_status = parse_pass_fail(config.recovery_status.as_str(), "--recovery-status")?;
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let checks = json!({
        "baseline_two_node_e2e": baseline_status,
        "tampered_signed_assignment_rejected": tamper_reject_status,
        "fail_closed_engaged": fail_closed_status,
        "netcheck_reports_fail_closed": netcheck_fail_closed_status,
        "recovery_restored_secure_runtime": recovery_status,
    });
    let status = if checks
        .as_object()
        .map(|items| {
            items
                .values()
                .all(|value| value.as_str() == Some(CHECK_PASS))
        })
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };
    let payload = json!({
        "phase": "phase10",
        "mode": "active_network_signed_state_tamper",
        "evidence_mode": "measured",
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": status,
        "hosts": {
            "exit_host": config.exit_host,
            "client_host": config.client_host,
        },
        "checks": checks,
        "evidence": {
            "status_after_tamper": config.status_after_tamper,
            "netcheck_after_tamper": config.netcheck_after_tamper,
            "status_after_recovery": config.status_after_recovery,
        },
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

pub fn execute_ops_write_active_network_rogue_path_hijack_report(
    config: WriteActiveNetworkRoguePathHijackReportConfig,
) -> Result<String, String> {
    let report_path = resolve_path(config.report_path.as_path())?;
    let rogue_endpoint_ip = config
        .rogue_endpoint_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| {
            format!(
                "invalid rogue endpoint IPv4 address {:?}: {err}",
                config.rogue_endpoint_ip
            )
        })?
        .to_string();
    let baseline_status = parse_pass_fail(config.baseline_status.as_str(), "--baseline-status")?;
    let hijack_reject_status = parse_pass_fail(
        config.hijack_reject_status.as_str(),
        "--hijack-reject-status",
    )?;
    let fail_closed_status =
        parse_pass_fail(config.fail_closed_status.as_str(), "--fail-closed-status")?;
    let netcheck_fail_closed_status = parse_pass_fail(
        config.netcheck_fail_closed_status.as_str(),
        "--netcheck-fail-closed-status",
    )?;
    let no_rogue_endpoint_status = parse_pass_fail(
        config.no_rogue_endpoint_status.as_str(),
        "--no-rogue-endpoint-status",
    )?;
    let recovery_status = parse_pass_fail(config.recovery_status.as_str(), "--recovery-status")?;
    let recovery_endpoint_status = parse_pass_fail(
        config.recovery_endpoint_status.as_str(),
        "--recovery-endpoint-status",
    )?;
    let captured_at_unix = if config.captured_at_unix == 0 {
        unix_now()
    } else {
        config.captured_at_unix
    };
    let captured_at = if config.captured_at_utc.trim().is_empty() {
        format!("{captured_at_unix}")
    } else {
        config.captured_at_utc.trim().to_string()
    };

    let checks = json!({
        "baseline_two_node_e2e": baseline_status,
        "forged_endpoint_assignment_rejected": hijack_reject_status,
        "fail_closed_engaged": fail_closed_status,
        "netcheck_reports_fail_closed": netcheck_fail_closed_status,
        "rogue_endpoint_not_adopted": no_rogue_endpoint_status,
        "recovery_restored_secure_runtime": recovery_status,
        "recovery_keeps_rogue_endpoint_rejected": recovery_endpoint_status,
    });
    let status = if checks
        .as_object()
        .map(|items| {
            items
                .values()
                .all(|value| value.as_str() == Some(CHECK_PASS))
        })
        .unwrap_or(false)
    {
        CHECK_PASS
    } else {
        CHECK_FAIL
    };
    let payload = json!({
        "phase": "phase10",
        "mode": "active_network_rogue_path_hijack",
        "evidence_mode": "measured",
        "captured_at": captured_at,
        "captured_at_unix": captured_at_unix,
        "status": status,
        "hosts": {
            "exit_host": config.exit_host,
            "client_host": config.client_host,
        },
        "rogue_endpoint_ip": rogue_endpoint_ip,
        "checks": checks,
        "evidence": {
            "wg_endpoints_before": config.endpoints_before,
            "wg_endpoints_after_hijack": config.endpoints_after_hijack,
            "wg_endpoints_after_recovery": config.endpoints_after_recovery,
            "status_after_hijack": config.status_after_hijack,
            "netcheck_after_hijack": config.netcheck_after_hijack,
            "status_after_recovery": config.status_after_recovery,
        },
    });
    write_json_pretty(report_path.as_path(), &payload)?;
    Ok(payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(CHECK_FAIL)
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        CheckLocalFileModeConfig, ExtractManagedDnsExpectedIpConfig,
        RewriteAssignmentMeshCidrConfig, RewriteAssignmentPeerEndpointIpConfig,
        UpdateRoleSwitchHostResultConfig, ValidateCrossNetworkForensicsBundleConfig,
        WriteActiveNetworkRoguePathHijackReportConfig,
        WriteActiveNetworkSignedStateTamperReportConfig, WriteLiveLabStageArtifactIndexConfig,
        WriteLiveLinuxControlSurfaceReportConfig, WriteLiveLinuxEndpointHijackReportConfig,
        WriteLiveLinuxLabRunSummaryConfig, WriteLiveLinuxRebootRecoveryReportConfig,
        WriteLiveLinuxServerIpBypassReportConfig, WriteRealWireguardExitnodeE2eReportConfig,
        WriteRoleSwitchMatrixReportConfig, count_no_leak_cleartext_packets,
        count_no_leak_tunnel_packets, dns_query_bind_addr, execute_ops_check_local_file_mode,
        execute_ops_extract_managed_dns_expected_ip, execute_ops_rewrite_assignment_mesh_cidr,
        execute_ops_rewrite_assignment_peer_endpoint_ip,
        execute_ops_update_role_switch_host_result,
        execute_ops_validate_cross_network_forensics_bundle,
        execute_ops_write_active_network_rogue_path_hijack_report,
        execute_ops_write_active_network_signed_state_tamper_report,
        execute_ops_write_live_lab_stage_artifact_index,
        execute_ops_write_live_linux_control_surface_report,
        execute_ops_write_live_linux_endpoint_hijack_report,
        execute_ops_write_live_linux_lab_run_summary,
        execute_ops_write_live_linux_reboot_recovery_report,
        execute_ops_write_live_linux_server_ip_bypass_report,
        execute_ops_write_real_wireguard_exitnode_e2e_report,
        execute_ops_write_role_switch_matrix_report, redact_forensics_payload,
    };
    use serde_json::Value;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("rustynet-cli-{name}-{stamp}"))
    }

    #[test]
    fn dns_query_bind_addr_prefers_loopback_for_loopback_server() {
        let bind = dns_query_bind_addr(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            bind,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        );
    }

    #[test]
    fn dns_query_bind_addr_uses_unspecified_for_non_loopback_server() {
        let bind = dns_query_bind_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(
            bind,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        );
    }

    #[test]
    fn dns_query_bind_addr_handles_ipv6_variants() {
        assert_eq!(
            dns_query_bind_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
        );
        assert_eq!(
            dns_query_bind_addr(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
    }

    #[test]
    fn owner_only_mode_check_rejects_group_bits() {
        let path = temp_path("mode-check");
        fs::write(path.as_path(), "secret").expect("write temp file");
        fs::set_permissions(path.as_path(), fs::Permissions::from_mode(0o640)).expect("set perms");
        let err = execute_ops_check_local_file_mode(CheckLocalFileModeConfig {
            path: path.clone(),
            policy: "owner-only".to_string(),
            label: "file".to_string(),
        })
        .expect_err("mode check should fail");
        assert!(err.contains("owner-only"));
        let _ = fs::remove_file(path.as_path());
    }

    #[test]
    fn redact_forensics_payload_hides_private_key_and_secret_values() {
        let input = "-----BEGIN PRIVATE KEY-----\npassword=abc123\ntoken: xyz\nsafe=value\n";
        let output = redact_forensics_payload(input);
        assert!(output.contains("[REDACTED sensitive key material]"));
        assert!(output.contains("password=<redacted>"));
        assert!(output.contains("token: <redacted>"));
        assert!(output.contains("safe=value"));
    }

    #[test]
    fn reboot_recovery_report_fails_when_client_reboot_missing() {
        let report_path = temp_path("reboot-report");
        let observations_path = temp_path("reboot-observations");
        fs::write(observations_path.as_path(), "client_reboot_wait=fail\n").expect("write obs");

        let err = execute_ops_write_live_linux_reboot_recovery_report(
            WriteLiveLinuxRebootRecoveryReportConfig {
                report_path: report_path.clone(),
                observations_path: observations_path.clone(),
                exit_pre: "a".to_string(),
                exit_post: "b".to_string(),
                client_pre: "c".to_string(),
                client_post: "".to_string(),
                exit_return: "pass".to_string(),
                exit_boot_change: "pass".to_string(),
                post_exit_dns_refresh: "pass".to_string(),
                post_exit_twohop: "pass".to_string(),
                client_return: "fail".to_string(),
                client_boot_change: "fail".to_string(),
                post_client_dns_refresh: "skipped".to_string(),
                post_client_twohop: "fail".to_string(),
                salvage_twohop: "skipped".to_string(),
            },
        )
        .expect_err("report should fail");
        assert!(err.contains("status is fail"));
        let body = fs::read_to_string(report_path.as_path()).expect("report present");
        assert!(body.contains("\"status\": \"fail\""));

        let _ = fs::remove_file(report_path.as_path());
        let _ = fs::remove_file(observations_path.as_path());
    }

    #[test]
    fn reboot_recovery_report_rejects_unknown_check_value() {
        let report_path = temp_path("reboot-report-invalid-check");
        let observations_path = temp_path("reboot-observations-invalid-check");
        fs::write(observations_path.as_path(), "").expect("write observations");

        let err = execute_ops_write_live_linux_reboot_recovery_report(
            WriteLiveLinuxRebootRecoveryReportConfig {
                report_path: report_path.clone(),
                observations_path: observations_path.clone(),
                exit_pre: "a".to_string(),
                exit_post: "b".to_string(),
                client_pre: "c".to_string(),
                client_post: "d".to_string(),
                exit_return: "pass".to_string(),
                exit_boot_change: "pass".to_string(),
                post_exit_dns_refresh: "invalid".to_string(),
                post_exit_twohop: "pass".to_string(),
                client_return: "pass".to_string(),
                client_boot_change: "pass".to_string(),
                post_client_dns_refresh: "pass".to_string(),
                post_client_twohop: "pass".to_string(),
                salvage_twohop: "skipped".to_string(),
            },
        )
        .expect_err("invalid check state should fail");
        assert!(err.contains("--post-exit-dns-refresh"));
        assert!(
            !report_path.exists(),
            "report should not be emitted when check-state parsing fails"
        );

        let _ = fs::remove_file(observations_path.as_path());
    }

    #[test]
    fn live_lab_run_summary_includes_parallel_worker_results() {
        let report_dir = temp_path("live-lab-summary");
        let state_dir = report_dir.join("state");
        fs::create_dir_all(state_dir.join("parallel-validate_baseline_runtime"))
            .expect("parallel stage dir");
        fs::write(
            state_dir.join("nodes.tsv"),
            "client\tdebian@client\tclient-1\tclient\n",
        )
        .expect("nodes write");
        fs::write(
            state_dir.join("stages.tsv"),
            "validate_baseline_runtime\thard\tfail\t1\t/tmp/stage.log\tbaseline validation failed\t2026-04-08T10:00:00Z\t2026-04-08T10:00:10Z\n",
        )
        .expect("stages write");
        fs::write(
            state_dir.join("parallel-validate_baseline_runtime/results.tsv"),
            "validate_baseline_runtime\tclient\tdebian@client\tclient-1\tclient\t1\t2026-04-08T10:00:00Z\t2026-04-08T10:00:10Z\t/tmp/client.log\t/tmp/snapshot.txt\t/tmp/route.txt\t/tmp/dns.txt\troute missing\n",
        )
        .expect("results write");

        let summary_json = report_dir.join("run_summary.json");
        let summary_md = report_dir.join("run_summary.md");
        execute_ops_write_live_linux_lab_run_summary(WriteLiveLinuxLabRunSummaryConfig {
            nodes_tsv: state_dir.join("nodes.tsv"),
            stages_tsv: state_dir.join("stages.tsv"),
            summary_json: summary_json.clone(),
            summary_md: summary_md.clone(),
            run_id: "run-1".to_string(),
            network_id: "net-1".to_string(),
            report_dir: report_dir.display().to_string(),
            overall_status: "fail".to_string(),
            started_at_local: "2026-04-08 11:00:00 UTC".to_string(),
            started_at_utc: "2026-04-08T10:00:00Z".to_string(),
            started_at_unix: 1,
            finished_at_local: "2026-04-08 11:00:10 UTC".to_string(),
            finished_at_utc: "2026-04-08T10:00:10Z".to_string(),
            finished_at_unix: 11,
            elapsed_secs: 10,
            elapsed_human: "00m 10s".to_string(),
        })
        .expect("summary should write");

        let payload: Value =
            serde_json::from_str(&fs::read_to_string(summary_json).expect("summary json"))
                .expect("summary json parses");
        let stages = payload
            .get("stages")
            .and_then(Value::as_array)
            .expect("stages array present");
        assert_eq!(stages.len(), 1);
        assert_eq!(
            stages[0].get("failed_worker_count").and_then(Value::as_u64),
            Some(1)
        );
        let worker_results = stages[0]
            .get("worker_results")
            .and_then(Value::as_array)
            .expect("worker results present");
        assert_eq!(worker_results.len(), 1);
        assert_eq!(
            worker_results[0]
                .get("snapshot_path")
                .and_then(Value::as_str),
            Some("/tmp/snapshot.txt")
        );

        let markdown = fs::read_to_string(summary_md).expect("summary md");
        assert!(markdown.contains("workers: 1/1 failed"));
        assert!(markdown.contains("snapshot: `/tmp/snapshot.txt`"));

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn role_switch_host_result_writer_sets_expected_checks() {
        let hosts_path = temp_path("role-switch-hosts");
        fs::write(hosts_path.as_path(), "{}\n").expect("write hosts");
        execute_ops_update_role_switch_host_result(UpdateRoleSwitchHostResultConfig {
            hosts_json_path: hosts_path.clone(),
            os_id: "debian13".to_string(),
            temp_role: "admin".to_string(),
            switch_execution: "pass".to_string(),
            post_switch_reconcile: "pass".to_string(),
            policy_still_enforced: "pass".to_string(),
            least_privilege_preserved: "pass".to_string(),
        })
        .expect("update host result");

        let body = fs::read_to_string(hosts_path.as_path()).expect("read hosts");
        assert!(body.contains("\"debian13\""));
        assert!(body.contains("\"switch_execution\": \"pass\""));
        let _ = fs::remove_file(hosts_path.as_path());
    }

    #[test]
    fn role_switch_report_writer_emits_measured_report() {
        let hosts_path = temp_path("role-switch-hosts-report");
        let report_path = temp_path("role-switch-report");
        let source_path = temp_path("role-switch-source");
        fs::write(
            hosts_path.as_path(),
            "{ \"ubuntu\": { \"checks\": { \"switch_execution\": \"pass\" } } }\n",
        )
        .expect("write hosts");
        fs::write(source_path.as_path(), "# source\n").expect("write source");

        execute_ops_write_role_switch_matrix_report(WriteRoleSwitchMatrixReportConfig {
            hosts_json_path: hosts_path.clone(),
            report_path: report_path.clone(),
            source_path: source_path.clone(),
            git_commit: "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            captured_at_unix: 1_772_983_200,
            overall_status: "pass".to_string(),
        })
        .expect("write report");

        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"evidence_mode\": \"measured\""));
        assert!(body.contains("\"status\": \"pass\""));
        assert!(body.contains("\"ubuntu\""));

        let _ = fs::remove_file(hosts_path.as_path());
        let _ = fs::remove_file(report_path.as_path());
        let _ = fs::remove_file(source_path.as_path());
    }

    #[test]
    fn server_ip_bypass_report_marks_pass_with_expected_routes() {
        let report_path = temp_path("server-ip-bypass-report");
        let status = execute_ops_write_live_linux_server_ip_bypass_report(
            WriteLiveLinuxServerIpBypassReportConfig {
                report_path: report_path.clone(),
                allowed_management_cidrs: "192.168.1.0/24".to_string(),
                probe_from_client_status: "pass".to_string(),
                probe_ip: "192.168.1.10".to_string(),
                probe_port: 18080,
                client_internet_route: "1.1.1.1 dev rustynet0".to_string(),
                client_probe_route: "192.168.1.10 dev eth0".to_string(),
                client_table_51820: "192.168.1.0/24 dev eth0\n10.0.0.0/8 dev rustynet0\n"
                    .to_string(),
                client_endpoints: "peer endpoints".to_string(),
                probe_self_test: "probe-ok".to_string(),
                probe_from_client_output: "blocked".to_string(),
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "pass");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"status\": \"pass\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn control_surface_report_fails_on_tcp_listener() {
        let work_dir = temp_path("control-surface-work");
        fs::create_dir_all(work_dir.as_path()).expect("mkdir");
        fs::write(
            work_dir.join("client.daemon_socket.txt"),
            "socket|600|root|root\n",
        )
        .expect("write daemon");
        fs::write(
            work_dir.join("client.helper_socket.txt"),
            "socket|660|root|rustynetd\n",
        )
        .expect("write helper");
        fs::write(
            work_dir.join("client.inet_listeners.txt"),
            "tcp LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:((\"rustynetd\",pid=1,fd=3))\n",
        )
        .expect("write listeners");
        fs::write(work_dir.join("client.managed_dns_state.txt"), "active\n").expect("write state");
        let report_path = temp_path("control-surface-report");
        let status = execute_ops_write_live_linux_control_surface_report(
            WriteLiveLinuxControlSurfaceReportConfig {
                report_path: report_path.clone(),
                dns_bind_addr: "127.0.0.1:53535".to_string(),
                remote_dns_probe_status: "pass".to_string(),
                remote_dns_probe_output: "{}".to_string(),
                work_dir: work_dir.clone(),
                host_labels: vec!["client".to_string()],
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "fail");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"status\": \"fail\""));

        let _ = fs::remove_file(work_dir.join("client.daemon_socket.txt"));
        let _ = fs::remove_file(work_dir.join("client.helper_socket.txt"));
        let _ = fs::remove_file(work_dir.join("client.inet_listeners.txt"));
        let _ = fs::remove_file(work_dir.join("client.managed_dns_state.txt"));
        let _ = fs::remove_dir(work_dir.as_path());
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn control_surface_report_accepts_rustynetd_owned_daemon_socket() {
        let work_dir = temp_path("control-surface-rustynetd-owner-work");
        fs::create_dir_all(work_dir.as_path()).expect("mkdir");
        fs::write(
            work_dir.join("client.daemon_socket.txt"),
            "socket|600|rustynetd|rustynetd\n",
        )
        .expect("write daemon");
        fs::write(
            work_dir.join("client.helper_socket.txt"),
            "socket|660|root|rustynetd\n",
        )
        .expect("write helper");
        fs::write(
            work_dir.join("client.inet_listeners.txt"),
            "udp UNCONN 0 0 127.0.0.1:53535 0.0.0.0:* users:((\"rustynetd\",pid=1,fd=4))\n",
        )
        .expect("write listeners");
        fs::write(work_dir.join("client.managed_dns_state.txt"), "active\n").expect("write state");
        let report_path = temp_path("control-surface-rustynetd-owner-report");
        let status = execute_ops_write_live_linux_control_surface_report(
            WriteLiveLinuxControlSurfaceReportConfig {
                report_path: report_path.clone(),
                dns_bind_addr: "127.0.0.1:53535".to_string(),
                remote_dns_probe_status: "pass".to_string(),
                remote_dns_probe_output: "{}".to_string(),
                work_dir: work_dir.clone(),
                host_labels: vec!["client".to_string()],
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "pass");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"status\": \"pass\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn rewrite_assignment_peer_endpoint_ip_updates_peer_entries() {
        let assignment_path = temp_path("assignment-endpoint-rewrite");
        fs::write(
            assignment_path.as_path(),
            "node_id=client-1\npeer.0.endpoint=192.168.18.49:51820\npeer.1.endpoint=192.168.18.51:51820\npeer.1.node_id=exit-1\n",
        )
        .expect("write assignment");
        let replaced = execute_ops_rewrite_assignment_peer_endpoint_ip(
            RewriteAssignmentPeerEndpointIpConfig {
                assignment_path: assignment_path.clone(),
                endpoint_ip: "203.0.113.10".to_string(),
            },
        )
        .expect("rewrite assignment");
        assert_eq!(replaced, "2");
        let body = fs::read_to_string(assignment_path.as_path()).expect("read assignment");
        assert!(body.contains("peer.0.endpoint=203.0.113.10:51820"));
        assert!(body.contains("peer.1.endpoint=203.0.113.10:51820"));
        let _ = fs::remove_file(assignment_path.as_path());
    }

    #[test]
    fn rewrite_assignment_mesh_cidr_updates_mesh_cidr_field() {
        let assignment_path = temp_path("assignment-mesh-cidr-rewrite");
        fs::write(
            assignment_path.as_path(),
            "node_id=client-1\nmesh_cidr=100.64.0.0/10\npeer.0.endpoint=192.168.18.49:51820\n",
        )
        .expect("write assignment");
        let rewritten = execute_ops_rewrite_assignment_mesh_cidr(RewriteAssignmentMeshCidrConfig {
            assignment_path: assignment_path.clone(),
            mesh_cidr: "100.128.0.0/10".to_string(),
        })
        .expect("rewrite mesh cidr");
        assert_eq!(rewritten, "100.128.0.0/10");
        let body = fs::read_to_string(assignment_path.as_path()).expect("read assignment");
        assert!(body.contains("mesh_cidr=100.128.0.0/10"));
        let _ = fs::remove_file(assignment_path.as_path());
    }

    #[test]
    fn endpoint_hijack_report_marks_fail_when_rogue_endpoint_present() {
        let report_path = temp_path("endpoint-hijack-report");
        let status = execute_ops_write_live_linux_endpoint_hijack_report(
            WriteLiveLinuxEndpointHijackReportConfig {
                report_path: report_path.clone(),
                rogue_endpoint_ip: "192.168.18.77".to_string(),
                baseline_status: "state=ExitActive restricted_safe_mode=false".to_string(),
                baseline_netcheck: "path_mode=direct_active".to_string(),
                baseline_endpoints: "peer-a=192.168.18.51:51820".to_string(),
                status_after_hijack: "state=FailClosed restricted_safe_mode=true".to_string(),
                netcheck_after_hijack: "path_mode=fail_closed".to_string(),
                endpoints_after_hijack: "peer-a=192.168.18.77:51820".to_string(),
                status_after_recovery: "state=ExitActive restricted_safe_mode=false".to_string(),
                endpoints_after_recovery: "peer-a=192.168.18.51:51820".to_string(),
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "fail");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"rogue_endpoint_not_adopted\": \"fail\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn real_wireguard_exitnode_report_marks_fail_when_dns_down_check_fails() {
        let report_path = temp_path("real-wireguard-exitnode-report");
        let status = execute_ops_write_real_wireguard_exitnode_e2e_report(
            WriteRealWireguardExitnodeE2eReportConfig {
                report_path: report_path.clone(),
                exit_status: "pass".to_string(),
                lan_off_status: "pass".to_string(),
                lan_on_status: "pass".to_string(),
                dns_up_status: "pass".to_string(),
                kill_switch_status: "pass".to_string(),
                dns_down_status: "fail".to_string(),
                environment: "lab-netns".to_string(),
                captured_at_utc: "2026-03-21T12:00:00Z".to_string(),
                captured_at_unix: 1_772_990_400,
            },
        )
        .expect("write report");
        assert_eq!(status, "fail");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"mode\": \"real_netns_wireguard\""));
        assert!(body.contains("\"dns_fail_close_when_tunnel_down\": \"fail\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn no_leak_packet_counters_detect_expected_patterns() {
        let load_lines = vec![
            "IP 172.16.10.2.12345 > 172.16.10.1.51820: UDP, length 64".to_string(),
            "IP 172.16.10.2.44444 > 198.18.0.1.53: UDP, length 32".to_string(),
        ];
        let down_lines = vec![
            "IP 172.16.10.2.55555 > 198.18.0.1.53: UDP, length 32".to_string(),
            "IP 172.16.10.2.66666 > 172.16.10.1.51820: UDP, length 64".to_string(),
        ];
        assert_eq!(count_no_leak_tunnel_packets(&load_lines), 1);
        assert_eq!(count_no_leak_cleartext_packets(&load_lines), 1);
        assert_eq!(count_no_leak_cleartext_packets(&down_lines), 1);
    }

    #[test]
    fn extract_managed_dns_expected_ip_supports_legacy_tokens() {
        let output = "dns inspect: state=valid fqdn=exit.rustynet expected_ip=100.64.0.1";
        let expected =
            execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
                fqdn: "exit.rustynet".to_string(),
                inspect_output: output.to_string(),
            })
            .expect("extract expected ip");
        assert_eq!(expected, "100.64.0.1");
    }

    #[test]
    fn extract_managed_dns_expected_ip_supports_record_indexed_tokens() {
        let output = "dns inspect: state=valid record_count=2 \
record.0.fqdn=client.rustynet record.0.expected_ip=100.68.223.117 \
record.1.fqdn=exit.rustynet record.1.expected_ip=100.109.33.213";
        let expected =
            execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
                fqdn: "exit.rustynet".to_string(),
                inspect_output: output.to_string(),
            })
            .expect("extract expected ip");
        assert_eq!(expected, "100.109.33.213");
    }

    #[test]
    fn signed_state_tamper_report_marks_pass_when_all_checks_pass() {
        let report_path = temp_path("signed-state-tamper-report");
        let status = execute_ops_write_active_network_signed_state_tamper_report(
            WriteActiveNetworkSignedStateTamperReportConfig {
                report_path: report_path.clone(),
                baseline_status: "pass".to_string(),
                tamper_reject_status: "pass".to_string(),
                fail_closed_status: "pass".to_string(),
                netcheck_fail_closed_status: "pass".to_string(),
                recovery_status: "pass".to_string(),
                exit_host: "192.168.18.49".to_string(),
                client_host: "192.168.18.50".to_string(),
                status_after_tamper: "state=FailClosed".to_string(),
                netcheck_after_tamper: "path_mode=fail_closed".to_string(),
                status_after_recovery: "state=ExitActive".to_string(),
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "pass");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"mode\": \"active_network_signed_state_tamper\""));
        assert!(body.contains("\"status\": \"pass\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn rogue_path_hijack_report_marks_fail_when_endpoint_check_fails() {
        let report_path = temp_path("rogue-path-hijack-report");
        let status = execute_ops_write_active_network_rogue_path_hijack_report(
            WriteActiveNetworkRoguePathHijackReportConfig {
                report_path: report_path.clone(),
                baseline_status: "pass".to_string(),
                hijack_reject_status: "pass".to_string(),
                fail_closed_status: "pass".to_string(),
                netcheck_fail_closed_status: "pass".to_string(),
                no_rogue_endpoint_status: "fail".to_string(),
                recovery_status: "pass".to_string(),
                recovery_endpoint_status: "pass".to_string(),
                rogue_endpoint_ip: "203.0.113.10".to_string(),
                exit_host: "192.168.18.49".to_string(),
                client_host: "192.168.18.50".to_string(),
                endpoints_before: "peer-a=192.168.18.49:51820".to_string(),
                endpoints_after_hijack: "peer-a=203.0.113.10:51820".to_string(),
                endpoints_after_recovery: "peer-a=192.168.18.49:51820".to_string(),
                status_after_hijack: "state=FailClosed".to_string(),
                netcheck_after_hijack: "path_mode=fail_closed".to_string(),
                status_after_recovery: "state=ExitActive".to_string(),
                captured_at_utc: "2026-03-21T10:00:00Z".to_string(),
                captured_at_unix: 1_772_983_200,
            },
        )
        .expect("write report");
        assert_eq!(status, "fail");
        let body = fs::read_to_string(report_path.as_path()).expect("read report");
        assert!(body.contains("\"mode\": \"active_network_rogue_path_hijack\""));
        assert!(body.contains("\"rogue_endpoint_not_adopted\": \"fail\""));
        let _ = fs::remove_file(report_path.as_path());
    }

    #[test]
    fn live_lab_stage_artifact_index_writes_recursive_file_index() {
        let stage_dir = temp_path("stage-artifact-index");
        let nested_dir = stage_dir.join("nested");
        fs::create_dir_all(&nested_dir).expect("nested dir");
        fs::write(stage_dir.join("alpha.txt"), "alpha").expect("alpha write");
        fs::write(nested_dir.join("beta.txt"), "beta").expect("beta write");
        fs::write(stage_dir.join("artifact_index.json"), "stale output").expect("stale write");

        let output = stage_dir.join("artifact_index.json");
        execute_ops_write_live_lab_stage_artifact_index(WriteLiveLabStageArtifactIndexConfig {
            stage_name: "cross_network_direct_remote_exit".to_string(),
            stage_dir: stage_dir.clone(),
            output: output.clone(),
        })
        .expect("artifact index should write");

        let payload: Value =
            serde_json::from_str(&fs::read_to_string(output.as_path()).expect("artifact json"))
                .expect("artifact json parses");
        assert_eq!(
            payload.get("mode").and_then(Value::as_str),
            Some("live_lab_stage_artifact_index")
        );
        assert_eq!(payload.get("file_count").and_then(Value::as_u64), Some(2));
        let files = payload
            .get("files")
            .and_then(Value::as_array)
            .expect("files array");
        assert_eq!(files.len(), 2);
        let relative_paths = files
            .iter()
            .filter_map(|entry| entry.get("relative_path").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(relative_paths.contains(&"alpha.txt"));
        assert!(relative_paths.contains(&"nested/beta.txt"));

        let _ = fs::remove_dir_all(stage_dir);
    }

    #[test]
    fn validate_cross_network_forensics_bundle_accepts_complete_bundle() {
        let stage_dir = temp_path("bundle-validation-pass");
        let node_dir = stage_dir.join("client");
        fs::create_dir_all(&node_dir).expect("node dir");
        fs::create_dir_all(stage_dir.join("nested")).expect("nested dir");
        fs::write(stage_dir.join("manifest.json"), r#"{"schema_version":1,"mode":"cross_network_failure_forensics","stage":"cross_network_direct_remote_exit","collected_at_utc":"2026-04-08T10:00:00Z","bundle_dir":"PLACEHOLDER","nodes":[{"label":"client","files":["client/service_snapshot.txt"]}]}"#).expect("manifest write");
        fs::write(
            stage_dir.join("route_matrix.txt"),
            "route_matrix_status=pass\n",
        )
        .expect("route matrix");
        fs::write(
            stage_dir.join("cluster_snapshot.txt"),
            "cluster_snapshot_status=pass\n",
        )
        .expect("cluster snapshot");

        for file_name in super::expected_forensics_node_files() {
            fs::write(node_dir.join(file_name), format!("{file_name}\n")).expect("node artifact");
        }

        let manifest_path = stage_dir.join("manifest.json");
        let manifest_body = fs::read_to_string(manifest_path.as_path()).expect("manifest read");
        let stage_dir_text = stage_dir.display().to_string();
        let manifest_body = manifest_body.replace("PLACEHOLDER", stage_dir_text.as_str());
        fs::write(manifest_path.as_path(), manifest_body).expect("manifest rewrite");

        fs::write(
            stage_dir.join("nodes.tsv"),
            "client\tdebian@client\tclient-1\tclient\n",
        )
        .expect("nodes write");

        let output = stage_dir.join("bundle_validation.json");
        execute_ops_validate_cross_network_forensics_bundle(
            ValidateCrossNetworkForensicsBundleConfig {
                nodes_tsv: stage_dir.join("nodes.tsv"),
                stage_name: "cross_network_direct_remote_exit".to_string(),
                stage_dir: stage_dir.clone(),
                output: output.clone(),
            },
        )
        .expect("bundle validation should pass");

        let payload: Value =
            serde_json::from_str(&fs::read_to_string(output.as_path()).expect("validation json"))
                .expect("validation json parses");
        assert_eq!(
            payload.get("bundle_status").and_then(Value::as_str),
            Some("pass")
        );
        assert_eq!(
            payload.get("missing_file_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            payload.get("empty_file_count").and_then(Value::as_u64),
            Some(0)
        );

        let _ = fs::remove_dir_all(stage_dir);
    }

    #[test]
    fn validate_cross_network_forensics_bundle_rejects_missing_artifacts() {
        let stage_dir = temp_path("bundle-validation-fail");
        let node_dir = stage_dir.join("client");
        fs::create_dir_all(&node_dir).expect("node dir");
        fs::write(
            stage_dir.join("manifest.json"),
            r#"{"schema_version":1,"mode":"cross_network_failure_forensics","stage":"cross_network_direct_remote_exit","collected_at_utc":"2026-04-08T10:00:00Z","bundle_dir":"PLACEHOLDER","nodes":[{"label":"client","files":["client/service_snapshot.txt"]}]}"#,
        )
        .expect("manifest write");
        fs::write(
            stage_dir.join("route_matrix.txt"),
            "route_matrix_status=pass\n",
        )
        .expect("route matrix");
        fs::write(
            stage_dir.join("cluster_snapshot.txt"),
            "cluster_snapshot_status=pass\n",
        )
        .expect("cluster snapshot");
        for file_name in super::expected_forensics_node_files() {
            if *file_name == "socket_snapshot.txt" {
                continue;
            }
            fs::write(node_dir.join(file_name), format!("{file_name}\n")).expect("node artifact");
        }

        let manifest_path = stage_dir.join("manifest.json");
        let manifest_body = fs::read_to_string(manifest_path.as_path()).expect("manifest read");
        let stage_dir_text = stage_dir.display().to_string();
        let manifest_body = manifest_body.replace("PLACEHOLDER", stage_dir_text.as_str());
        fs::write(manifest_path.as_path(), manifest_body).expect("manifest rewrite");

        fs::write(
            stage_dir.join("nodes.tsv"),
            "client\tdebian@client\tclient-1\tclient\n",
        )
        .expect("nodes write");

        let output = stage_dir.join("bundle_validation.json");
        let err = execute_ops_validate_cross_network_forensics_bundle(
            ValidateCrossNetworkForensicsBundleConfig {
                nodes_tsv: stage_dir.join("nodes.tsv"),
                stage_name: "cross_network_direct_remote_exit".to_string(),
                stage_dir: stage_dir.clone(),
                output: output.clone(),
            },
        )
        .expect_err("bundle validation should fail");
        assert!(err.contains("bundle validation failed"));

        let payload: Value =
            serde_json::from_str(&fs::read_to_string(output.as_path()).expect("validation json"))
                .expect("validation json parses");
        assert_eq!(
            payload.get("bundle_status").and_then(Value::as_str),
            Some("fail")
        );
        assert!(
            payload
                .get("missing_file_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
                > 0
        );

        let _ = fs::remove_dir_all(stage_dir);
    }
}
