//! Read-only VM-lab network audit and preflight (rulebook Slice A).
//!
//! Everything in this module observes and validates; nothing mutates a VM,
//! UTM configuration, host route, firewall, or the inventory. Live state is
//! collected through argv-only invocations of read-only tools (`plutil`,
//! `utmctl list`, `ifconfig`, `netstat`, `scutil`, `ssh` with fixed command
//! strings) and evaluated against the typed network-profile model.
//!
//! Evidence is written atomically to a redacted `vm_network_evidence.json`.
//! Secrets are excluded structurally (they are never copied into evidence
//! types) and a final serialized-output guard aborts the write if any known
//! secret value would leak anyway.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::network_profile::{
    AttachmentMode, CapabilitySupport, DEFAULT_NETWORK_PROFILE_DIR, IpCidr, MESH_OVERLAY_CIDR,
    NetworkEvidenceStatus, NetworkProfile, NetworkProfileId, UtmBackend,
    backend_attachment_support, backend_multi_nic_support, load_network_profile_dir,
    mesh_overlay_cidr,
};
use super::{VmController, VmGuestPlatform, VmInventoryEntry};

const DEFAULT_EVIDENCE_PATH: &str = "state/vm_network_evidence.json";
const NETNS_SIM_SCRIPT_RELATIVE_PATH: &str = "scripts/vm_lab/netns_internet_sim.sh";
const UTM_APP_INFO_PLIST: &str = "/Applications/UTM.app/Contents/Info.plist";
const PLUTIL_PATH: &str = "/usr/bin/plutil";
const EVIDENCE_SCHEMA_VERSION: u32 = 1;
const GUEST_SSH_CONNECT_TIMEOUT_SECS: u32 = 6;
const GUEST_OBSERVATION_SECTION_SEPARATOR: &str = "__RUSTYNET_NET_AUDIT_SECTION__";
/// Fixed, constant guest observation command lines (no interpolation of any
/// runtime value — rulebook: no shell construction from untrusted values).
const LINUX_GUEST_OBSERVATION_COMMAND: &str = "ip -o addr show 2>/dev/null; echo __RUSTYNET_NET_AUDIT_SECTION__; ip -o link show 2>/dev/null; echo __RUSTYNET_NET_AUDIT_SECTION__; ip route show 2>/dev/null; echo __RUSTYNET_NET_AUDIT_SECTION__; cat /etc/resolv.conf 2>/dev/null";
const MACOS_GUEST_OBSERVATION_COMMAND: &str = "/sbin/ifconfig -a 2>/dev/null; echo __RUSTYNET_NET_AUDIT_SECTION__; echo; echo __RUSTYNET_NET_AUDIT_SECTION__; /usr/sbin/netstat -rn -f inet 2>/dev/null; echo __RUSTYNET_NET_AUDIT_SECTION__; /usr/sbin/scutil --dns 2>/dev/null";

/// Config for `rustynet ops vm-lab-network-audit` (read-only report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabNetworkAuditConfig {
    pub inventory_path: Option<PathBuf>,
    pub profile_dir: Option<PathBuf>,
    /// Optional profile to evaluate drift against. Without it the audit
    /// still validates all manifests and reports observed state + findings.
    pub profile: Option<String>,
    pub utmctl_path: Option<PathBuf>,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub output_path: Option<PathBuf>,
    pub skip_guests: bool,
    pub repo_root: Option<PathBuf>,
}

/// Config for `rustynet ops vm-lab-network-preflight` (read-only gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabNetworkPreflightConfig {
    pub inventory_path: Option<PathBuf>,
    pub profile_dir: Option<PathBuf>,
    /// Required: preflight is always evaluated against one profile.
    pub profile: String,
    pub utmctl_path: Option<PathBuf>,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub output_path: Option<PathBuf>,
    pub skip_guests: bool,
    pub repo_root: Option<PathBuf>,
}

// --- Observation model (everything here is redacted-by-construction) ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UtmNicObservation {
    pub index: usize,
    pub mode: AttachmentMode,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolate_from_host: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forward_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UtmVmObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_alias: Option<String>,
    pub utm_name: String,
    pub bundle_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<UtmBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_state: Option<String>,
    pub nics: Vec<UtmNicObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInterfaceObservation {
    pub name: String,
    pub ipv4: Vec<String>,
    pub ipv6_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostRouteObservation {
    pub destination: String,
    pub interface: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct HostProxyObservation {
    pub socks_enabled: bool,
    pub http_enabled: bool,
    pub https_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct HostNetworkObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utm_version: Option<String>,
    pub interfaces: Vec<HostInterfaceObservation>,
    pub routes: Vec<HostRouteObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_route_interface: Option<String>,
    pub vpn_utun_interfaces: Vec<String>,
    pub full_tunnel_vpn_suspected: bool,
    pub proxy: HostProxyObservation,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observation_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestInterfaceObservation {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestNetworkObservation {
    pub alias: String,
    /// collected | unreachable | not_supported | skipped
    pub status: String,
    pub interfaces: Vec<GuestInterfaceObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_route_interface: Option<String>,
    pub dns_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Non-secret projection of an inventory entry. `ssh_password`,
/// `parent_device`, and other operator-private fields are intentionally not
/// representable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InventoryEntrySnapshot {
    pub alias: String,
    pub ssh_target_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utm_name: Option<String>,
    pub has_local_utm_controller: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubstrateSourceObservation {
    pub script_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_wan_cidr: Option<String>,
    pub collides_with_mesh: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditFinding {
    pub severity: FindingSeverity,
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl AuditFinding {
    fn error(kind: &str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Error,
            kind: kind.to_owned(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    fn warning(kind: &str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Warning,
            kind: kind.to_owned(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    fn info(kind: &str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Info,
            kind: kind.to_owned(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceProfileRef {
    pub id: String,
    pub digest: String,
    pub evidence_tier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendCapabilityEntry {
    pub backend: UtmBackend,
    pub attachment: AttachmentMode,
    pub support: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmNetworkEvidence {
    pub schema_version: u32,
    pub tool: String,
    pub read_only: bool,
    pub generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_dirty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_profile: Option<EvidenceProfileRef>,
    pub validated_profiles: Vec<EvidenceProfileRef>,
    pub host: HostNetworkObservation,
    pub vms: Vec<UtmVmObservation>,
    pub unmanaged_utm_vms: Vec<String>,
    pub guests: Vec<GuestNetworkObservation>,
    pub inventory_path: String,
    pub inventory_entries: Vec<InventoryEntrySnapshot>,
    pub substrate_sources: Vec<SubstrateSourceObservation>,
    pub backend_capabilities: Vec<BackendCapabilityEntry>,
    pub multi_nic_support: BTreeMap<String, CapabilitySupport>,
    pub findings: Vec<AuditFinding>,
    pub overall_status: NetworkEvidenceStatus,
    pub status_reason: String,
    pub evidence_limitations: Vec<String>,
}

// --- Pure parsers (fixture-testable, no process execution) ---

/// Parse `utmctl list` output into (name, status) pairs. Names may contain
/// spaces; the row shape is `UUID STATUS NAME...`.
pub fn parse_utmctl_list(output: &str) -> Vec<(String, String)> {
    let mut vms = Vec::new();
    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(3, char::is_whitespace);
        let (Some(_uuid), Some(status)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };
        vms.push((name.trim().to_owned(), status.trim().to_owned()));
    }
    vms
}

/// Parse the JSON emitted by `plutil -extract Network json` for one backend.
/// Required keys missing or unknown modes fail closed with an error.
pub fn parse_utm_nics_json(
    backend: UtmBackend,
    json: &str,
) -> Result<Vec<UtmNicObservation>, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|err| format!("UTM network configuration is not valid JSON: {err}"))?;
    let array = value
        .as_array()
        .ok_or_else(|| "UTM network configuration is not an array".to_owned())?;
    let mut nics = Vec::new();
    for (index, entry) in array.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("UTM network adapter {index} is not an object"))?;
        let mode_raw = object
            .get("Mode")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("UTM network adapter {index} is missing Mode"))?;
        let mode = AttachmentMode::parse_utm(mode_raw, backend)?;
        let mac = object
            .get("MacAddress")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("UTM network adapter {index} is missing MacAddress"))?;
        let normalized_mac = normalize_mac(mac)
            .ok_or_else(|| format!("UTM network adapter {index} has invalid MAC {mac:?}"))?;
        let bridge_interface = object
            .get("BridgeInterface")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let hardware = object
            .get("Hardware")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let isolate_from_host = object
            .get("IsolateFromHost")
            .and_then(serde_json::Value::as_bool);
        let port_forward_count = object
            .get("PortForward")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len);
        nics.push(UtmNicObservation {
            index,
            mode,
            mac: normalized_mac,
            bridge_interface,
            hardware,
            isolate_from_host,
            port_forward_count,
        });
    }
    Ok(nics)
}

fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut normalized = Vec::with_capacity(6);
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        normalized.push(format!("{:0>2}", part.to_ascii_lowercase()));
    }
    Some(normalized.join(":"))
}

/// Parse `ifconfig -a` output into interface observations, redacting
/// non-private addresses.
pub fn parse_ifconfig(output: &str) -> Vec<HostInterfaceObservation> {
    let mut interfaces: Vec<HostInterfaceObservation> = Vec::new();
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some((name, _rest)) = line.split_once(':')
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric())
            {
                interfaces.push(HostInterfaceObservation {
                    name: name.to_owned(),
                    ipv4: Vec::new(),
                    ipv6_count: 0,
                });
            }
            continue;
        }
        let Some(current) = interfaces.last_mut() else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(addr) = rest.split_whitespace().next() {
                current.ipv4.push(redact_ip_str(addr));
            }
        } else if trimmed.starts_with("inet6 ") {
            current.ipv6_count += 1;
        }
    }
    interfaces
}

/// Normalize a macOS `netstat -rn` destination into a full CIDR string.
/// Handles `default`, classful shorthand (`127`, `10.230.76/24`), bare host
/// addresses, and explicit CIDRs. Returns `None` for link/IPv6 rows.
pub fn normalize_route_destination(raw: &str) -> Option<String> {
    if raw == "default" {
        return Some("default".to_owned());
    }
    let (addr_part, prefix_part) = match raw.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (raw, None),
    };
    let octets: Vec<&str> = addr_part.split('.').collect();
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let mut parsed = Vec::with_capacity(4);
    for octet in &octets {
        let value: u8 = octet.parse().ok()?;
        parsed.push(value);
    }
    let octet_count = parsed.len();
    while parsed.len() < 4 {
        parsed.push(0);
    }
    let prefix: u8 = match prefix_part {
        Some(p) => p.parse().ok().filter(|p| *p <= 32)?,
        None => {
            if octet_count == 4 {
                32
            } else {
                (octet_count as u8) * 8
            }
        }
    };
    let addr = Ipv4Addr::new(parsed[0], parsed[1], parsed[2], parsed[3]);
    // Mask host bits so the result is always a valid network address.
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = Ipv4Addr::from(u32::from(addr) & mask);
    Some(format!("{network}/{prefix}"))
}

/// Parse `netstat -rn -f inet` output into route observations. Gateways are
/// dropped; destinations are normalized and redacted.
pub fn parse_netstat_routes(output: &str) -> Vec<HostRouteObservation> {
    let mut routes = Vec::new();
    let mut in_ipv4_section = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Destination") {
            in_ipv4_section = true;
            continue;
        }
        if !in_ipv4_section || trimmed.is_empty() {
            continue;
        }
        let columns: Vec<&str> = trimmed.split_whitespace().collect();
        if columns.len() < 4 {
            continue;
        }
        let Some(destination) = normalize_route_destination(columns[0]) else {
            continue;
        };
        // Netif column position varies with the Expire column; take the
        // first column after Flags that looks like an interface name.
        let interface = columns
            .iter()
            .skip(3)
            .find(|c| {
                c.chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_alphabetic())
                    && c.chars().all(|ch| ch.is_ascii_alphanumeric())
            })
            .map(|c| (*c).to_owned());
        let Some(interface) = interface else {
            continue;
        };
        routes.push(HostRouteObservation {
            destination: redact_route_destination(&destination),
            interface,
        });
    }
    routes
}

/// Parse `scutil --proxy` output.
pub fn parse_scutil_proxy(output: &str) -> HostProxyObservation {
    let mut proxy = HostProxyObservation::default();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let enabled = value.trim() == "1";
            match key {
                "SOCKSEnable" => proxy.socks_enabled = enabled,
                "HTTPEnable" => proxy.http_enabled = enabled,
                "HTTPSEnable" => proxy.https_enabled = enabled,
                _ => {}
            }
        }
    }
    proxy
}

fn is_private_v4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
        || addr.is_unspecified()
}

/// Redact any address that is not clearly lab-internal. Private ranges
/// (RFC 1918, CGNAT, loopback, link-local, ULA, IPv6 link-local) are kept;
/// everything else — public addresses in particular — is replaced.
pub fn redact_ip_str(raw: &str) -> String {
    let bare = raw.split('%').next().unwrap_or(raw);
    if let Ok(v4) = bare.parse::<Ipv4Addr>() {
        if is_private_v4(v4) {
            return raw.to_owned();
        }
        return "public-redacted".to_owned();
    }
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        let segments = v6.segments();
        let is_ula = (segments[0] & 0xfe00) == 0xfc00;
        let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
        if v6.is_loopback() || is_ula || is_link_local {
            return raw.to_owned();
        }
        return "public-redacted".to_owned();
    }
    raw.to_owned()
}

fn redact_route_destination(destination: &str) -> String {
    if destination == "default" {
        return destination.to_owned();
    }
    let Some((addr, prefix)) = destination.split_once('/') else {
        return redact_ip_str(destination);
    };
    let redacted = redact_ip_str(addr);
    if redacted == "public-redacted" {
        format!("public-redacted/{prefix}")
    } else {
        destination.to_owned()
    }
}

/// Parse Linux `ip -o addr show` + `ip -o link show` + `ip route show` +
/// resolv.conf sections into a guest observation.
pub fn parse_linux_guest_sections(alias: &str, raw: &str) -> GuestNetworkObservation {
    let sections: Vec<&str> = raw.split(GUEST_OBSERVATION_SECTION_SEPARATOR).collect();
    let addr_section = sections.first().copied().unwrap_or_default();
    let link_section = sections.get(1).copied().unwrap_or_default();
    let route_section = sections.get(2).copied().unwrap_or_default();
    let resolv_section = sections.get(3).copied().unwrap_or_default();

    let mut interfaces: BTreeMap<String, GuestInterfaceObservation> = BTreeMap::new();
    for line in link_section.lines() {
        // `2: enp0s1: <...> mtu 1500 ... link/ether 3e:ae:a9:5a:61:82 ...`
        let mut parts = line.split_whitespace();
        let Some(_index) = parts.next() else { continue };
        let Some(name_raw) = parts.next() else {
            continue;
        };
        let name = name_raw.trim_end_matches(':').to_owned();
        if name.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mtu = tokens
            .iter()
            .position(|t| *t == "mtu")
            .and_then(|pos| tokens.get(pos + 1))
            .and_then(|value| value.parse().ok());
        let mac = tokens
            .iter()
            .position(|t| *t == "link/ether")
            .and_then(|pos| tokens.get(pos + 1))
            .and_then(|value| normalize_mac(value));
        interfaces.insert(
            name.clone(),
            GuestInterfaceObservation {
                name,
                mac,
                ipv4: Vec::new(),
                ipv6_count: 0,
                mtu,
            },
        );
    }
    for line in addr_section.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 4 {
            continue;
        }
        let name = tokens[1].trim_end_matches(':').to_owned();
        let entry = interfaces
            .entry(name.clone())
            .or_insert_with(|| GuestInterfaceObservation {
                name,
                mac: None,
                ipv4: Vec::new(),
                ipv6_count: 0,
                mtu: None,
            });
        match tokens[2] {
            "inet" => {
                if let Some(addr) = tokens.get(3) {
                    entry.ipv4.push(redact_ip_str(addr));
                }
            }
            "inet6" => entry.ipv6_count += 1,
            _ => {}
        }
    }
    let default_route_interface = route_section.lines().find_map(|line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() == Some(&"default") {
            tokens
                .iter()
                .position(|t| *t == "dev")
                .and_then(|pos| tokens.get(pos + 1))
                .map(|dev| (*dev).to_owned())
        } else {
            None
        }
    });
    let dns_servers = resolv_section
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("nameserver")
                .map(|rest| redact_ip_str(rest.trim()))
        })
        .collect();
    GuestNetworkObservation {
        alias: alias.to_owned(),
        status: "collected".to_owned(),
        interfaces: interfaces.into_values().collect(),
        default_route_interface,
        dns_servers,
        error: None,
    }
}

/// Parse macOS guest sections (ifconfig / spacer / netstat / scutil --dns).
pub fn parse_macos_guest_sections(alias: &str, raw: &str) -> GuestNetworkObservation {
    let sections: Vec<&str> = raw.split(GUEST_OBSERVATION_SECTION_SEPARATOR).collect();
    let ifconfig_section = sections.first().copied().unwrap_or_default();
    let netstat_section = sections.get(2).copied().unwrap_or_default();
    let dns_section = sections.get(3).copied().unwrap_or_default();

    let host_interfaces = parse_ifconfig(ifconfig_section);
    let interfaces = host_interfaces
        .into_iter()
        .map(|iface| GuestInterfaceObservation {
            name: iface.name,
            mac: None,
            ipv4: iface.ipv4,
            ipv6_count: iface.ipv6_count,
            mtu: None,
        })
        .collect();
    let default_route_interface = parse_netstat_routes(netstat_section)
        .into_iter()
        .find(|route| route.destination == "default")
        .map(|route| route.interface);
    let dns_servers = dns_section
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver[") {
                trimmed
                    .split_once(':')
                    .map(|(_, addr)| redact_ip_str(addr.trim()))
            } else {
                None
            }
        })
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    GuestNetworkObservation {
        alias: alias.to_owned(),
        status: "collected".to_owned(),
        interfaces,
        default_route_interface,
        dns_servers,
        error: None,
    }
}

/// Read the netns simulator's declared WAN CIDR from its script source
/// (deterministic read-only drift check for the mesh/transit collision).
pub fn parse_netns_sim_wan_cidr(script_source: &str) -> Option<String> {
    for line in script_source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("WAN_CIDR=") {
            let value = rest.trim_matches(|c| c == '"' || c == '\'');
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

// --- Pure validation over observations ---

fn inventory_snapshot(entries: &[VmInventoryEntry]) -> Vec<InventoryEntrySnapshot> {
    entries
        .iter()
        .map(|entry| {
            let utm_name = entry
                .controller
                .as_ref()
                .and_then(|controller| match controller {
                    VmController::LocalUtm { utm_name, .. } => Some(utm_name.clone()),
                    VmController::Libvirt { .. } => None,
                });
            InventoryEntrySnapshot {
                alias: entry.alias.clone(),
                ssh_target_host: redact_ip_str(ssh_target_host(&entry.ssh_target)),
                last_known_ip: entry.last_known_ip.as_deref().map(redact_ip_str),
                last_known_network: entry.last_known_network.clone(),
                network_group: entry.network_group.clone(),
                mesh_ip: entry.mesh_ip.as_deref().map(redact_ip_str),
                utm_name,
                has_local_utm_controller: matches!(
                    entry.controller,
                    Some(VmController::LocalUtm { .. })
                ),
            }
        })
        .collect()
}

fn ssh_target_host(target: &str) -> &str {
    target
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target)
}

/// Extract the trailing CIDR from a network-group label like
/// `utm-shared-192.168.64.0/24` or `lan-192.168.0.0/24`.
fn network_group_cidr(label: &str) -> Option<IpCidr> {
    let candidate = label.rsplit('-').next()?;
    IpCidr::parse(candidate).ok()
}

/// Inventory-level staleness and duplicate detection.
pub fn detect_inventory_findings(entries: &[VmInventoryEntry]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut recorded_ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in entries {
        let host = ssh_target_host(&entry.ssh_target);
        if host.parse::<Ipv4Addr>().is_ok() {
            recorded_ips
                .entry(host.to_owned())
                .or_default()
                .push(entry.alias.clone());
        }
        if let Some(last_known) = &entry.last_known_ip
            && last_known != host
            && last_known.parse::<Ipv4Addr>().is_ok()
        {
            recorded_ips
                .entry(last_known.clone())
                .or_default()
                .push(entry.alias.clone());
        }
    }
    for (ip, mut aliases) in recorded_ips {
        aliases.sort();
        aliases.dedup();
        if aliases.len() > 1 {
            findings.push(AuditFinding::error(
                "duplicate_recorded_ip",
                aliases.join(","),
                format!(
                    "inventory records the same address {} for multiple entries; at least one is stale",
                    redact_ip_str(&ip)
                ),
            ));
        }
    }
    for entry in entries {
        let Some(group) = &entry.network_group else {
            continue;
        };
        let Some(group_cidr) = network_group_cidr(group) else {
            findings.push(AuditFinding::warning(
                "unparseable_network_group",
                entry.alias.clone(),
                format!("network_group label {group:?} does not end in a parseable CIDR"),
            ));
            continue;
        };
        if let Some(last_known) = &entry.last_known_ip
            && let Ok(addr) = last_known.parse::<Ipv4Addr>()
            && !group_cidr.contains_v4(addr)
        {
            findings.push(AuditFinding::error(
                        "stale_network_group",
                        entry.alias.clone(),
                        format!(
                            "network_group {group:?} does not contain the recorded address {}; the label is stale",
                            redact_ip_str(last_known)
                        ),
                    ));
        }
    }
    findings
}

/// Cross-fleet L2 reachability check. [`detect_profile_drift_findings`] validates
/// only the UTM attachment *mode*, and [`detect_inventory_findings`] validates a
/// node's recorded IP against its *own* `network_group` label — neither notices a
/// node that is mode-compliant (`Shared`) yet stranded on a different subnet than
/// the rest of the fleet, so it cannot reach its peers at L2 and cannot mesh
/// (observed with macOS `vmnet` handing a "Shared" NIC a real-LAN lease instead
/// of the internal plane, on a config byte-identical to a working node).
///
/// The expected fleet plane is the modal `network_group` CIDR across the
/// inventory (the plane most nodes declare). A reachable guest is flagged when its
/// *live observed* underlay IPv4 is not inside that plane. Fail-safe: with fewer
/// than two nodes agreeing on a plane there is no authoritative fleet, and nothing
/// is flagged.
pub fn detect_offfleet_subnet_findings(
    guests: &[GuestNetworkObservation],
    entries: &[VmInventoryEntry],
) -> Vec<AuditFinding> {
    let mut planes: Vec<(IpCidr, usize)> = Vec::new();
    for entry in entries {
        if let Some(group) = &entry.network_group
            && let Some(cidr) = network_group_cidr(group)
        {
            if let Some(slot) = planes.iter_mut().find(|(existing, _)| *existing == cidr) {
                slot.1 += 1;
            } else {
                planes.push((cidr, 1));
            }
        }
    }
    // Deterministic modal plane: most votes, then the lexicographically smallest
    // CIDR string to break ties reproducibly.
    planes.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
    });
    let (fleet_cidr, votes) = match planes.first() {
        Some(&(cidr, votes)) if votes >= 2 => (cidr, votes),
        _ => return Vec::new(),
    };

    let mesh = mesh_overlay_cidr();
    let mut findings = Vec::new();
    for guest in guests {
        if guest.status != "collected" {
            continue;
        }
        let Some(observed) = guest_underlay_ipv4(guest, &mesh) else {
            continue;
        };
        if !fleet_cidr.contains_v4(observed) {
            findings.push(AuditFinding::error(
                "off_fleet_subnet",
                guest.alias.clone(),
                format!(
                    "live underlay address {} is not on the fleet management plane {} (shared by \
                     {votes} inventory nodes); the NIC is attachment-mode compliant but on a \
                     different L2, so this node cannot reach its peers and cannot mesh. Repair: \
                     regenerate this VM's MAC or re-create its NIC in the UTM app — the attachment \
                     mode is already correct, so a mode rewrite (vm-lab-network-prepare) alone will \
                     not move it onto the fleet plane.",
                    redact_ip_str(&observed.to_string()),
                    fleet_cidr,
                ),
            ));
        }
    }
    findings
}

/// The guest's primary underlay IPv4: the first routable address on its
/// default-route interface (falling back to any non-loopback interface),
/// excluding loopback, link-local, and mesh-overlay addresses — i.e. the address
/// that determines which L2 plane the node sits on.
fn guest_underlay_ipv4(guest: &GuestNetworkObservation, mesh: &IpCidr) -> Option<Ipv4Addr> {
    let ordered: Vec<&GuestInterfaceObservation> = match &guest.default_route_interface {
        Some(default_iface) => {
            let mut ifaces: Vec<&GuestInterfaceObservation> = guest
                .interfaces
                .iter()
                .filter(|iface| &iface.name == default_iface)
                .collect();
            ifaces.extend(
                guest
                    .interfaces
                    .iter()
                    .filter(|iface| &iface.name != default_iface),
            );
            ifaces
        }
        None => guest.interfaces.iter().collect(),
    };
    for iface in ordered {
        if iface.name == "lo" {
            continue;
        }
        for raw in &iface.ipv4 {
            let addr_part = raw.split('/').next().unwrap_or("");
            let Ok(addr) = addr_part.parse::<Ipv4Addr>() else {
                continue;
            };
            if addr.is_loopback() || addr.is_link_local() || mesh.contains_v4(addr) {
                continue;
            }
            return Some(addr);
        }
    }
    None
}

/// UTM attachment findings that apply regardless of any selected profile.
pub fn detect_attachment_findings(vms: &[UtmVmObservation]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut macs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for vm in vms {
        let subject = vm
            .inventory_alias
            .clone()
            .unwrap_or_else(|| vm.utm_name.clone());
        if let Some(error) = &vm.observation_error {
            findings.push(AuditFinding::error(
                "utm_observation_failed",
                subject.clone(),
                error.clone(),
            ));
            continue;
        }
        for nic in &vm.nics {
            macs.entry(nic.mac.clone())
                .or_default()
                .push(format!("{subject}#nic{}", nic.index));
            if nic.mode == AttachmentMode::Bridged {
                match nic.bridge_interface.as_deref() {
                    None => findings.push(AuditFinding::error(
                        "bridged_interface_unpinned",
                        subject.clone(),
                        format!(
                            "NIC {} is Bridged with no pinned host interface; attachment meaning depends on ambient host state",
                            nic.index
                        ),
                    )),
                    Some("en0") => findings.push(AuditFinding::error(
                        "bridged_to_everyday_lan",
                        subject.clone(),
                        format!(
                            "NIC {} is bridged to en0, the host's everyday LAN; this is never a default lab attachment",
                            nic.index
                        ),
                    )),
                    Some(_) => {}
                }
            }
        }
        if vm.backend == Some(UtmBackend::Apple) && vm.nics.len() > 1 {
            findings.push(AuditFinding::info(
                "apple_multi_nic_unproven",
                subject,
                "Apple backend multi-NIC behavior is not live-proven in this lab; treat as unavailable until proven",
            ));
        }
    }
    for (mac, mut owners) in macs {
        owners.sort();
        owners.dedup();
        if owners.len() > 1 {
            findings.push(AuditFinding::error(
                "duplicate_mac",
                owners.join(","),
                format!("MAC address {mac} is assigned to multiple adapters"),
            ));
        }
    }
    findings
}

/// Profile-drift findings for one selected profile.
pub fn detect_profile_drift_findings(
    profile: &NetworkProfile,
    vms: &[UtmVmObservation],
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for vm in vms {
        let subject = vm
            .inventory_alias
            .clone()
            .unwrap_or_else(|| vm.utm_name.clone());
        if vm.observation_error.is_some() {
            continue;
        }
        let Some(backend) = vm.backend else {
            continue;
        };
        if let Err(reason) = profile.backend_compatibility(backend) {
            findings.push(AuditFinding {
                severity: FindingSeverity::Warning,
                kind: "backend_not_supported".to_owned(),
                subject: subject.clone(),
                detail: reason,
            });
            continue;
        }
        let Some(management_nic) = vm.nics.first() else {
            findings.push(AuditFinding::error(
                "missing_management_adapter",
                subject.clone(),
                "VM has no network adapter at all; the management plane is absent",
            ));
            continue;
        };
        if !profile.management.attachment.permits(management_nic.mode) {
            findings.push(AuditFinding::error(
                "management_attachment_drift",
                subject.clone(),
                format!(
                    "management NIC mode is {} but profile {} requires {:?}",
                    management_nic.mode, profile.id, profile.management.attachment
                ),
            ));
        }
        let scenario_required = profile.scenario.substrate
            != super::network_profile::ScenarioSubstrate::None
            && profile.scenario.substrate != super::network_profile::ScenarioSubstrate::Netns;
        if scenario_required {
            match vm.nics.get(1) {
                None => findings.push(AuditFinding::warning(
                    "scenario_nic_missing",
                    subject.clone(),
                    format!(
                        "profile {} requires a scenario NIC but the VM has only the management adapter; the substrate has not been prepared",
                        profile.id
                    ),
                )),
                Some(scenario_nic) => {
                    if profile.scenario.substrate
                        == super::network_profile::ScenarioSubstrate::PhysicalInterface
                    {
                        let allowed = profile
                            .scenario
                            .physical
                            .as_ref()
                            .map(|physical| physical.allowed_host_interfaces.as_slice())
                            .unwrap_or(&[]);
                        match scenario_nic.bridge_interface.as_deref() {
                            Some(interface) if allowed.iter().any(|a| a == interface) => {}
                            Some(interface) => findings.push(AuditFinding::error(
                                "scenario_interface_not_allowlisted",
                                subject.clone(),
                                format!(
                                    "scenario NIC bridges to {interface:?}, which is not in the profile allowlist"
                                ),
                            )),
                            None => findings.push(AuditFinding::error(
                                "scenario_interface_unpinned",
                                subject.clone(),
                                "scenario NIC is bridged with no pinned interface",
                            )),
                        }
                    }
                }
            }
        } else if vm.nics.len() > 1 {
            findings.push(AuditFinding::warning(
                "extra_adapter",
                subject.clone(),
                format!(
                    "VM has {} adapters but profile {} expects only the management plane",
                    vm.nics.len(),
                    profile.id
                ),
            ));
        }
    }
    findings
}

/// Host-route overlap detection against the mesh and (optionally) a
/// profile's declared scenario subnets.
pub fn detect_host_route_findings(
    host: &HostNetworkObservation,
    profile: Option<&NetworkProfile>,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mesh = mesh_overlay_cidr();
    let mut protected: Vec<(String, IpCidr)> = vec![("mesh".to_owned(), mesh)];
    if let Some(profile) = profile {
        if let Some(transit) = &profile.scenario.transit_subnet {
            protected.push((format!("profile {} transit", profile.id), *transit));
        }
        if let Some(pool) = &profile.scenario.site_subnet_pool {
            protected.push((format!("profile {} site pool", profile.id), *pool));
        }
    }
    if host.full_tunnel_vpn_suspected {
        findings.push(AuditFinding::warning(
            "host_full_tunnel_vpn",
            host.vpn_utun_interfaces.join(","),
            "a full-tunnel VPN appears active on the host; Shared-attachment guest egress meaning depends on it and it must be recorded as an environmental condition",
        ));
    }
    if host.proxy.socks_enabled {
        findings.push(AuditFinding::error(
            "host_socks_proxy_active",
            "host",
            "a SOCKS proxy is active on the host; SOCKS bootstrap contaminates network evidence and must be absent during evidence stages",
        ));
    }
    for route in &host.routes {
        if route.destination == "default" || route.destination.starts_with("public-redacted") {
            continue;
        }
        let Ok(route_cidr) = IpCidr::parse(&route.destination) else {
            continue;
        };
        // /1 routes are the full-tunnel pattern, already reported above.
        if route_cidr.prefix() <= 1 {
            continue;
        }
        for (label, protected_cidr) in &protected {
            if route_cidr.overlaps(protected_cidr) {
                let is_vpn = host.vpn_utun_interfaces.contains(&route.interface);
                findings.push(AuditFinding::error(
                    "host_route_collision",
                    route.interface.clone(),
                    format!(
                        "host route {} via {}{} overlaps {label} ({protected_cidr})",
                        route.destination,
                        route.interface,
                        if is_vpn { " (VPN)" } else { "" },
                    ),
                ));
            }
        }
    }
    findings
}

/// Substrate source drift: the netns simulator's declared WAN vs the mesh.
pub fn detect_substrate_findings(sources: &[SubstrateSourceObservation]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for source in sources {
        if let Some(error) = &source.error {
            findings.push(AuditFinding::warning(
                "substrate_source_unreadable",
                source.script_path.clone(),
                error.clone(),
            ));
            continue;
        }
        if source.collides_with_mesh {
            findings.push(AuditFinding::error(
                "netns_transit_mesh_collision",
                source.script_path.clone(),
                format!(
                    "the netns simulator declares WAN transit {} which overlaps the Rustynet mesh {MESH_OVERLAY_CIDR}; ordinary transit must move to 198.18.0.0/15 before daemon-path evidence is accepted (rulebook §15.3)",
                    source.declared_wan_cidr.as_deref().unwrap_or("<unknown>")
                ),
            ));
        }
    }
    findings
}

/// Compute the overall external status from the findings.
pub fn overall_status_from_findings(
    findings: &[AuditFinding],
    profile_selected: bool,
) -> (NetworkEvidenceStatus, String) {
    let error_count = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Error)
        .count();
    if error_count > 0 {
        return (
            NetworkEvidenceStatus::Fail,
            format!("{error_count} error finding(s); see findings"),
        );
    }
    if profile_selected {
        if findings.iter().any(|f| f.kind == "backend_not_supported") {
            return (
                NetworkEvidenceStatus::NotSupported,
                "a backend cannot satisfy the selected profile".to_owned(),
            );
        }
        if findings.iter().any(|f| f.kind == "scenario_nic_missing") {
            return (
                NetworkEvidenceStatus::NotRun,
                "the scenario substrate for the selected profile is not prepared; no evidence claim".to_owned(),
            );
        }
    }
    (
        NetworkEvidenceStatus::Pass,
        "all executed read-only checks passed".to_owned(),
    )
}

// --- Secret guard + atomic writer ---

/// Abort evidence writes that would contain any known secret value. This is
/// defense-in-depth behind the structural exclusion of secrets from the
/// evidence types.
pub fn ensure_no_secret_values(serialized: &str, banned_values: &[String]) -> Result<(), String> {
    for banned in banned_values {
        if banned.len() >= 3 && serialized.contains(banned.as_str()) {
            return Err(
                "evidence serialization contains a secret value; refusing to write".to_owned(),
            );
        }
    }
    Ok(())
}

/// Atomic owner-only evidence write: temp file + rename, 0600.
pub fn write_evidence_atomic(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create evidence dir failed ({}): {err}", parent.display()))?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("evidence path {} has no filename", path.display()))?;
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp"));
    fs::write(&tmp_path, contents)
        .map_err(|err| format!("write evidence temp failed ({}): {err}", tmp_path.display()))?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "set evidence permissions failed ({}): {err}",
            tmp_path.display()
        )
    })?;
    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "rename evidence into place failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(())
}

// --- Live collectors (argv-only, read-only) ---

fn run_read_only(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program} invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{program} produced non-UTF-8 output"))
}

/// Deadline for a single `plutil` read of a UTM `config.plist`. A healthy read
/// is sub-millisecond; the bound only exists to survive a config file whose
/// *content* read blocks indefinitely (observed after a host power loss left a
/// UTM bundle on a wedged APFS inode — `stat` still worked so enumeration
/// reached the file, but every `open`+`read` hung). Discovery enumerates every
/// registered VM, so one unreadable bundle must not wedge the whole run.
const PLUTIL_READ_TIMEOUT: Duration = Duration::from_secs(8);

/// `run_read_only` with a hard wall-clock bound. `Command::output()` blocks
/// until the child exits, so a `plutil` that hangs on an unreadable file would
/// hang the caller forever. Spawn, poll `try_wait`, and SIGKILL past the
/// deadline, surfacing a timeout error the caller records as an observation
/// error (the VM is skipped) rather than propagating the hang.
fn run_read_only_bounded(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{program} invocation failed: {err}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{program} timed out after {}s (unreadable config?)",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(format!("{program} wait failed: {err}")),
        }
    }
    // The child has exited; `wait_with_output` returns immediately and drains
    // the (tiny) captured stdout/stderr.
    let output = child
        .wait_with_output()
        .map_err(|err| format!("{program} output collection failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{program} produced non-UTF-8 output"))
}

fn plutil_extract(config_path: &Path, key: &str, format: &str) -> Result<String, String> {
    let path_str = config_path
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 path {}", config_path.display()))?;
    run_read_only_bounded(
        PLUTIL_PATH,
        &["-extract", key, format, "-o", "-", path_str],
        PLUTIL_READ_TIMEOUT,
    )
    .map(|out| out.trim().to_owned())
}

fn observe_utm_vm(
    alias: Option<&str>,
    utm_name: &str,
    bundle_path: &Path,
    power_state: Option<&str>,
) -> UtmVmObservation {
    let config_path = bundle_path.join("config.plist");
    let mut observation = UtmVmObservation {
        inventory_alias: alias.map(str::to_owned),
        utm_name: utm_name.to_owned(),
        bundle_path: bundle_path.display().to_string(),
        backend: None,
        configuration_version: None,
        power_state: power_state.map(str::to_owned),
        nics: Vec::new(),
        observation_error: None,
    };
    if !config_path.is_file() {
        observation.observation_error = Some(format!(
            "UTM bundle config not found at {}",
            config_path.display()
        ));
        return observation;
    }
    let backend = match plutil_extract(&config_path, "Backend", "raw")
        .and_then(|raw| UtmBackend::parse(&raw))
    {
        Ok(backend) => backend,
        Err(err) => {
            observation.observation_error = Some(err);
            return observation;
        }
    };
    observation.backend = Some(backend);
    observation.configuration_version = plutil_extract(&config_path, "ConfigurationVersion", "raw")
        .ok()
        .and_then(|raw| raw.parse().ok());
    match plutil_extract(&config_path, "Network", "json")
        .and_then(|json| parse_utm_nics_json(backend, &json))
    {
        Ok(nics) => observation.nics = nics,
        Err(err) => observation.observation_error = Some(err),
    }
    observation
}

/// Parse `ip -j addr show` (iproute2 JSON) into interface observations,
/// redacting non-private IPv4 addresses. The Linux run-on-host analogue of
/// `parse_ifconfig`.
pub fn parse_ip_json_addr(output: &str) -> Vec<HostInterfaceObservation> {
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_str::<serde_json::Value>(output)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|iface| {
            let name = iface.get("ifname")?.as_str()?.to_owned();
            let mut ipv4 = Vec::new();
            let mut ipv6_count = 0usize;
            if let Some(addrs) = iface.get("addr_info").and_then(serde_json::Value::as_array) {
                for addr in addrs {
                    match addr.get("family").and_then(serde_json::Value::as_str) {
                        Some("inet") => {
                            if let Some(local) =
                                addr.get("local").and_then(serde_json::Value::as_str)
                            {
                                ipv4.push(redact_ip_str(local));
                            }
                        }
                        Some("inet6") => ipv6_count += 1,
                        _ => {}
                    }
                }
            }
            Some(HostInterfaceObservation {
                name,
                ipv4,
                ipv6_count,
            })
        })
        .collect()
}

/// Parse `ip -j route show` (iproute2 JSON) into route observations. The Linux
/// run-on-host analogue of `parse_netstat_routes`; `dst` is already a CIDR or
/// the literal `default`.
pub fn parse_ip_json_route(output: &str) -> Vec<HostRouteObservation> {
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_str::<serde_json::Value>(output)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|route| {
            let dst = route.get("dst").and_then(serde_json::Value::as_str)?;
            let dev = route
                .get("dev")
                .and_then(serde_json::Value::as_str)?
                .to_owned();
            let destination = normalize_route_destination(dst)?;
            Some(HostRouteObservation {
                destination: redact_route_destination(&destination),
                interface: dev,
            })
        })
        .collect()
}

/// Resolve the iproute2 `ip` binary. A non-login/service PATH can omit
/// `/usr/sbin`, so probe the standard locations before falling back to a bare
/// PATH lookup.
fn linux_ip_binary() -> String {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if Path::new(candidate).is_file() {
            return candidate.to_owned();
        }
    }
    "ip".to_owned()
}

/// macOS/UTM host observation: UTM version from the app bundle plus the
/// BSD-tool network collectors (`ifconfig`/`netstat`/`scutil`).
fn observe_host_macos(host: &mut HostNetworkObservation, utmctl_available: bool) {
    if Path::new(UTM_APP_INFO_PLIST).is_file() {
        match plutil_extract(
            Path::new(UTM_APP_INFO_PLIST),
            "CFBundleShortVersionString",
            "raw",
        ) {
            Ok(version) => host.utm_version = Some(version),
            Err(err) => host.observation_errors.push(err),
        }
    } else if utmctl_available {
        host.observation_errors
            .push("UTM.app Info.plist not found; UTM version unknown".to_owned());
    }
    match run_read_only("/sbin/ifconfig", &["-a"]) {
        Ok(output) => host.interfaces = parse_ifconfig(&output),
        Err(err) => host.observation_errors.push(err),
    }
    match run_read_only("/usr/sbin/netstat", &["-rn", "-f", "inet"]) {
        Ok(output) => host.routes = parse_netstat_routes(&output),
        Err(err) => host.observation_errors.push(err),
    }
    match run_read_only("/usr/sbin/scutil", &["--proxy"]) {
        Ok(output) => host.proxy = parse_scutil_proxy(&output),
        Err(err) => host.observation_errors.push(err),
    }
}

/// Linux (dedicated libvirt VM host, LinuxVmHostPlan) host observation via
/// iproute2 JSON. Linux has no system-wide proxy configuration analogous to
/// macOS `scutil --proxy`, so the proxy observation is left at its disabled
/// default.
fn observe_host_linux(host: &mut HostNetworkObservation) {
    let ip_bin = linux_ip_binary();
    match run_read_only(ip_bin.as_str(), &["-j", "addr", "show"]) {
        Ok(output) => host.interfaces = parse_ip_json_addr(&output),
        Err(err) => host.observation_errors.push(err),
    }
    match run_read_only(ip_bin.as_str(), &["-j", "route", "show"]) {
        Ok(output) => host.routes = parse_ip_json_route(&output),
        Err(err) => host.observation_errors.push(err),
    }
}

fn observe_host(utmctl_available: bool) -> HostNetworkObservation {
    let mut host = HostNetworkObservation::default();
    // The lab robot runs either on the macOS/UTM host or, for the dedicated
    // Linux libvirt VM host (LinuxVmHostPlan), on a Linux host. Collect host
    // network state with the tools native to whichever OS it is running on.
    if std::env::consts::OS == "macos" {
        observe_host_macos(&mut host, utmctl_available);
    } else {
        observe_host_linux(&mut host);
    }
    host.default_route_interface = host
        .routes
        .iter()
        .find(|route| route.destination == "default")
        .map(|route| route.interface.clone());
    host.vpn_utun_interfaces = host
        .interfaces
        .iter()
        .filter(|iface| iface.name.starts_with("utun"))
        .map(|iface| iface.name.clone())
        .collect();
    let default_via_utun = host
        .default_route_interface
        .as_deref()
        .is_some_and(|iface| iface.starts_with("utun"));
    let split_default_via_utun = host.routes.iter().any(|route| {
        route.interface.starts_with("utun")
            && (route.destination == "0.0.0.0/1" || route.destination == "128.0.0.0/1")
    });
    host.full_tunnel_vpn_suspected = default_via_utun || split_default_via_utun;
    host
}

fn observe_guest(
    entry: &VmInventoryEntry,
    identity_file: &Path,
    known_hosts: &Path,
) -> GuestNetworkObservation {
    let platform = entry.platform.or_else(|| {
        entry.os.as_deref().map(|os| {
            let lowered = os.to_ascii_lowercase();
            if lowered.contains("mac") {
                VmGuestPlatform::Macos
            } else if lowered.contains("windows") {
                VmGuestPlatform::Windows
            } else {
                VmGuestPlatform::Linux
            }
        })
    });
    let command = match platform {
        Some(VmGuestPlatform::Linux) | None => LINUX_GUEST_OBSERVATION_COMMAND,
        Some(VmGuestPlatform::Macos) => MACOS_GUEST_OBSERVATION_COMMAND,
        Some(VmGuestPlatform::Windows | VmGuestPlatform::Ios | VmGuestPlatform::Android) => {
            return GuestNetworkObservation {
                alias: entry.alias.clone(),
                status: "not_supported".to_owned(),
                interfaces: Vec::new(),
                default_route_interface: None,
                dns_servers: Vec::new(),
                error: Some(
                    "guest network observation is not implemented for this platform in Slice A"
                        .to_owned(),
                ),
            };
        }
    };
    if !identity_file.is_file() {
        return GuestNetworkObservation {
            alias: entry.alias.clone(),
            status: "unreachable".to_owned(),
            interfaces: Vec::new(),
            default_route_interface: None,
            dns_servers: Vec::new(),
            error: Some(format!(
                "lab SSH identity {} not found; password authentication is never used for audit",
                identity_file.display()
            )),
        };
    }
    let host = ssh_target_host(&entry.ssh_target).to_owned();
    let destination = match entry.ssh_user.as_deref() {
        Some(user) => format!("{user}@{host}"),
        None => host,
    };
    let identity = identity_file.display().to_string();
    let known_hosts_arg = format!("UserKnownHostsFile={}", known_hosts.display());
    let connect_timeout = format!("ConnectTimeout={GUEST_SSH_CONNECT_TIMEOUT_SECS}");
    let args = [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        known_hosts_arg.as_str(),
        "-o",
        connect_timeout.as_str(),
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        identity.as_str(),
        destination.as_str(),
        "--",
        command,
    ];
    match run_read_only("/usr/bin/ssh", &args) {
        Ok(output) => match platform {
            Some(VmGuestPlatform::Macos) => parse_macos_guest_sections(&entry.alias, &output),
            _ => parse_linux_guest_sections(&entry.alias, &output),
        },
        Err(err) => GuestNetworkObservation {
            alias: entry.alias.clone(),
            status: "unreachable".to_owned(),
            interfaces: Vec::new(),
            default_route_interface: None,
            dns_servers: Vec::new(),
            error: Some(err),
        },
    }
}

fn observe_substrate_sources(repo_root: &Path) -> Vec<SubstrateSourceObservation> {
    let script_path = repo_root.join(NETNS_SIM_SCRIPT_RELATIVE_PATH);
    let mesh = mesh_overlay_cidr();
    let observation = match fs::read_to_string(&script_path) {
        Ok(source) => {
            let declared = parse_netns_sim_wan_cidr(&source);
            let collides = declared
                .as_deref()
                .and_then(|cidr| IpCidr::parse(cidr).ok())
                .is_some_and(|cidr| cidr.overlaps(&mesh));
            SubstrateSourceObservation {
                script_path: NETNS_SIM_SCRIPT_RELATIVE_PATH.to_owned(),
                declared_wan_cidr: declared,
                collides_with_mesh: collides,
                error: None,
            }
        }
        Err(err) => SubstrateSourceObservation {
            script_path: NETNS_SIM_SCRIPT_RELATIVE_PATH.to_owned(),
            declared_wan_cidr: None,
            collides_with_mesh: false,
            error: Some(format!("cannot read simulator script: {err}")),
        },
    };
    vec![observation]
}

fn git_head_and_dirty(repo_root: &Path) -> (Option<String>, Option<bool>) {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_owned());
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(repo_root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.is_empty());
    (commit, dirty)
}

fn backend_capability_matrix() -> Vec<BackendCapabilityEntry> {
    let backends = [UtmBackend::Qemu, UtmBackend::Apple];
    let modes = [
        AttachmentMode::Shared,
        AttachmentMode::HostOnly,
        AttachmentMode::Bridged,
        AttachmentMode::Emulated,
    ];
    let mut entries = Vec::new();
    for backend in backends {
        for mode in modes {
            entries.push(BackendCapabilityEntry {
                backend,
                attachment: mode,
                support: backend_attachment_support(backend, mode),
            });
        }
    }
    entries
}

// --- Command execution ---

struct ObservationRun {
    evidence: VmNetworkEvidence,
    banned_values: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_network_observation(
    tool: &str,
    inventory_path: &Path,
    profile_dir: &Path,
    selected_profile: Option<&str>,
    utmctl_path: &Path,
    identity_file: &Path,
    known_hosts: &Path,
    skip_guests: bool,
    repo_root: &Path,
) -> Result<ObservationRun, String> {
    let profiles = load_network_profile_dir(profile_dir)?;
    let selected = match selected_profile {
        Some(raw) => {
            let id = NetworkProfileId::parse(raw)?;
            Some(profiles.get(&id).ok_or_else(|| {
                format!(
                    "network profile {raw:?} not found in {} (available: {})",
                    profile_dir.display(),
                    profiles
                        .keys()
                        .map(NetworkProfileId::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?)
        }
        None => None,
    };

    let entries = super::load_inventory(inventory_path)?;
    let banned_values: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry.ssh_password.clone())
        .collect();

    let utmctl_available = utmctl_path.is_file();
    let power_states: BTreeMap<String, String> = if utmctl_available {
        let utmctl = utmctl_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 utmctl path {}", utmctl_path.display()))?;
        match run_read_only(utmctl, &["list"]) {
            Ok(output) => parse_utmctl_list(&output).into_iter().collect(),
            Err(_) => BTreeMap::new(),
        }
    } else {
        BTreeMap::new()
    };

    let mut vms = Vec::new();
    let mut inventory_utm_names = BTreeSet::new();
    for entry in &entries {
        let Some(VmController::LocalUtm {
            utm_name,
            bundle_path,
        }) = entry.controller.as_ref()
        else {
            continue;
        };
        inventory_utm_names.insert(utm_name.clone());
        vms.push(observe_utm_vm(
            Some(entry.alias.as_str()),
            utm_name,
            bundle_path,
            power_states.get(utm_name).map(String::as_str),
        ));
    }
    let unmanaged_utm_vms: Vec<String> = power_states
        .keys()
        .filter(|name| !inventory_utm_names.contains(*name))
        .cloned()
        .collect();

    let host = observe_host(utmctl_available);

    let guests: Vec<GuestNetworkObservation> = if skip_guests {
        entries
            .iter()
            .filter(|entry| entry.controller.is_some())
            .map(|entry| GuestNetworkObservation {
                alias: entry.alias.clone(),
                status: "skipped".to_owned(),
                interfaces: Vec::new(),
                default_route_interface: None,
                dns_servers: Vec::new(),
                error: None,
            })
            .collect()
    } else {
        entries
            .iter()
            .filter(|entry| entry.controller.is_some())
            .map(|entry| observe_guest(entry, identity_file, known_hosts))
            .collect()
    };

    let substrate_sources = observe_substrate_sources(repo_root);

    let mut findings = Vec::new();
    findings.extend(detect_inventory_findings(&entries));
    findings.extend(detect_offfleet_subnet_findings(&guests, &entries));
    findings.extend(detect_attachment_findings(&vms));
    if let Some(profile) = selected {
        findings.extend(detect_profile_drift_findings(profile, &vms));
    }
    findings.extend(detect_host_route_findings(&host, selected));
    findings.extend(detect_substrate_findings(&substrate_sources));
    for name in &unmanaged_utm_vms {
        findings.push(AuditFinding::info(
            "unmanaged_utm_vm",
            name.clone(),
            "UTM knows this VM but the lab inventory does not; it is outside lab management",
        ));
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.subject.cmp(&b.subject))
    });

    let (overall_status, status_reason) =
        overall_status_from_findings(&findings, selected.is_some());

    let (git_commit, git_dirty) = git_head_and_dirty(repo_root);
    let generated_at_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let evidence = VmNetworkEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        tool: tool.to_owned(),
        read_only: true,
        generated_at_epoch_secs,
        git_commit,
        git_dirty,
        selected_profile: selected.map(|profile| EvidenceProfileRef {
            id: profile.id.as_str().to_owned(),
            digest: profile.canonical_digest(),
            evidence_tier: profile.evidence_tier.as_str().to_owned(),
        }),
        validated_profiles: profiles
            .values()
            .map(|profile| EvidenceProfileRef {
                id: profile.id.as_str().to_owned(),
                digest: profile.canonical_digest(),
                evidence_tier: profile.evidence_tier.as_str().to_owned(),
            })
            .collect(),
        host,
        vms,
        unmanaged_utm_vms,
        guests,
        inventory_path: inventory_path.display().to_string(),
        inventory_entries: inventory_snapshot(&entries),
        substrate_sources,
        backend_capabilities: backend_capability_matrix(),
        multi_nic_support: [
            (
                UtmBackend::Qemu.as_str().to_owned(),
                backend_multi_nic_support(UtmBackend::Qemu),
            ),
            (
                UtmBackend::Apple.as_str().to_owned(),
                backend_multi_nic_support(UtmBackend::Apple),
            ),
        ]
        .into_iter()
        .collect(),
        findings,
        overall_status,
        status_reason,
        evidence_limitations: vec![
            "read-only audit: reports observed state; it proves no dataplane behavior".to_owned(),
            "management reachability is not dataplane proof (rulebook §3)".to_owned(),
            "single-host observation cannot prove remote-network independence".to_owned(),
        ],
    };
    Ok(ObservationRun {
        evidence,
        banned_values,
    })
}

fn write_evidence_and_summarize(
    run: &ObservationRun,
    output_path: &Path,
) -> Result<String, String> {
    let serialized = serde_json::to_string_pretty(&run.evidence)
        .map_err(|err| format!("serialize evidence failed: {err}"))?;
    ensure_no_secret_values(&serialized, &run.banned_values)?;
    write_evidence_atomic(output_path, &serialized)?;
    let evidence = &run.evidence;
    let mut summary = String::new();
    summary.push_str(&format!(
        "tool={} read_only=true overall_status={} reason={:?}\n",
        evidence.tool, evidence.overall_status, evidence.status_reason
    ));
    if let Some(profile) = &evidence.selected_profile {
        summary.push_str(&format!(
            "profile={} digest={} tier={}\n",
            profile.id, profile.digest, profile.evidence_tier
        ));
    }
    summary.push_str(&format!(
        "profiles_validated={} vms_observed={} unmanaged_utm_vms={} guests_collected={}\n",
        evidence.validated_profiles.len(),
        evidence.vms.len(),
        evidence.unmanaged_utm_vms.len(),
        evidence
            .guests
            .iter()
            .filter(|guest| guest.status == "collected")
            .count(),
    ));
    for vm in &evidence.vms {
        let nic_summary: Vec<String> = vm
            .nics
            .iter()
            .map(|nic| {
                let bridge = nic
                    .bridge_interface
                    .as_deref()
                    .map(|iface| format!("->{iface}"))
                    .unwrap_or_default();
                format!("nic{}={}{bridge}", nic.index, nic.mode)
            })
            .collect();
        summary.push_str(&format!(
            "vm={} backend={} power={} {}\n",
            vm.inventory_alias.as_deref().unwrap_or(&vm.utm_name),
            vm.backend.map(UtmBackend::as_str).unwrap_or("unknown"),
            vm.power_state.as_deref().unwrap_or("unknown"),
            if nic_summary.is_empty() {
                "nics=none".to_owned()
            } else {
                nic_summary.join(" ")
            },
        ));
    }
    let errors = evidence
        .findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Error)
        .count();
    let warnings = evidence
        .findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Warning)
        .count();
    summary.push_str(&format!(
        "findings: {errors} error(s), {warnings} warning(s)\n"
    ));
    for finding in &evidence.findings {
        summary.push_str(&format!(
            "  [{}] {} ({}): {}\n",
            match finding.severity {
                FindingSeverity::Error => "ERROR",
                FindingSeverity::Warning => "WARN",
                FindingSeverity::Info => "INFO",
            },
            finding.kind,
            finding.subject,
            finding.detail
        ));
    }
    summary.push_str(&format!("evidence={}\n", output_path.display()));
    Ok(summary)
}

/// `rustynet ops vm-lab-network-audit`: read-only observation + findings.
/// The command succeeds when the audit itself completes; findings are
/// reported in the summary and evidence, never repaired.
pub fn execute_ops_vm_lab_network_audit(config: VmLabNetworkAuditConfig) -> Result<String, String> {
    let repo_root = config.repo_root.unwrap_or_else(|| PathBuf::from("."));
    let run = run_network_observation(
        "vm-lab-network-audit",
        &config
            .inventory_path
            .unwrap_or_else(|| PathBuf::from(super::DEFAULT_VM_LAB_INVENTORY_PATH)),
        &config
            .profile_dir
            .unwrap_or_else(|| PathBuf::from(DEFAULT_NETWORK_PROFILE_DIR)),
        config.profile.as_deref(),
        &config
            .utmctl_path
            .unwrap_or_else(super::default_utmctl_path),
        &config
            .ssh_identity_file
            .unwrap_or_else(super::default_lab_ssh_identity_path),
        &config
            .known_hosts_path
            .unwrap_or_else(super::default_known_hosts_path),
        config.skip_guests,
        &repo_root,
    )?;
    let output_path = config
        .output_path
        .unwrap_or_else(|| PathBuf::from(DEFAULT_EVIDENCE_PATH));
    write_evidence_and_summarize(&run, &output_path)
}

/// `rustynet ops vm-lab-network-preflight`: read-only fail-closed gate
/// against one required profile. Any status other than `pass` is an error.
pub fn execute_ops_vm_lab_network_preflight(
    config: VmLabNetworkPreflightConfig,
) -> Result<String, String> {
    let repo_root = config.repo_root.unwrap_or_else(|| PathBuf::from("."));
    let run = run_network_observation(
        "vm-lab-network-preflight",
        &config
            .inventory_path
            .unwrap_or_else(|| PathBuf::from(super::DEFAULT_VM_LAB_INVENTORY_PATH)),
        &config
            .profile_dir
            .unwrap_or_else(|| PathBuf::from(DEFAULT_NETWORK_PROFILE_DIR)),
        Some(config.profile.as_str()),
        &config
            .utmctl_path
            .unwrap_or_else(super::default_utmctl_path),
        &config
            .ssh_identity_file
            .unwrap_or_else(super::default_lab_ssh_identity_path),
        &config
            .known_hosts_path
            .unwrap_or_else(super::default_known_hosts_path),
        config.skip_guests,
        &repo_root,
    )?;
    let output_path = config
        .output_path
        .unwrap_or_else(|| PathBuf::from(DEFAULT_EVIDENCE_PATH));
    let status = run.evidence.overall_status;
    let summary = write_evidence_and_summarize(&run, &output_path)?;
    if status != NetworkEvidenceStatus::Pass {
        return Err(format!(
            "network preflight did not pass (status={status}); a run must stop before deployment or signed-state mutation\n{summary}"
        ));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::super::network_profile::parse_network_profile_toml;
    use super::*;

    const QEMU_SHARED_NIC_JSON: &str = r#"[{"PortForward": [], "MacAddress": "3E:AE:A9:5A:61:82", "Hardware": "virtio-net-pci", "Mode": "Shared", "IsolateFromHost": false}]"#;
    const QEMU_HOST_ONLY_NIC_JSON: &str = r#"[{"PortForward": [], "MacAddress": "3E:AE:A9:5A:61:83", "Hardware": "virtio-net-pci", "Mode": "Host", "IsolateFromHost": false}]"#;
    const QEMU_BRIDGED_EN0_NIC_JSON: &str = r#"[{"PortForward": [], "MacAddress": "7A:C9:3C:84:1B:99", "Hardware": "virtio-net-pci", "BridgeInterface": "en0", "Mode": "Bridged", "IsolateFromHost": false}]"#;
    const QEMU_BRIDGED_UNPINNED_NIC_JSON: &str = r#"[{"PortForward": [], "MacAddress": "7A:F1:41:67:E3:A7", "Hardware": "virtio-net-pci", "Mode": "Bridged", "IsolateFromHost": false}]"#;
    const APPLE_SHARED_NIC_JSON: &str =
        r#"[{"MacAddress": "32:6b:39:df:d7:4e", "Mode": "Shared"}]"#;
    const APPLE_BRIDGED_NIC_JSON: &str =
        r#"[{"MacAddress": "32:6b:39:df:d7:4f", "Mode": "Bridged", "BridgeInterface": "en5"}]"#;

    #[test]
    fn parse_ip_json_addr_reads_interfaces_and_redacts() {
        let output = r#"[
          {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8},{"family":"inet6","local":"::1","prefixlen":128}]},
          {"ifname":"br0","addr_info":[
            {"family":"inet","local":"192.168.0.50","prefixlen":24},
            {"family":"inet","local":"8.8.8.8","prefixlen":32},
            {"family":"inet6","local":"fe80::5054:ff:fe12:3456","prefixlen":64}
          ]}
        ]"#;
        let interfaces = parse_ip_json_addr(output);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "lo");
        assert_eq!(interfaces[0].ipv4, vec!["127.0.0.1".to_owned()]);
        assert_eq!(interfaces[0].ipv6_count, 1);
        assert_eq!(interfaces[1].name, "br0");
        // Private IPv4 kept, public IPv4 redacted, IPv6 only counted.
        assert_eq!(
            interfaces[1].ipv4,
            vec!["192.168.0.50".to_owned(), "public-redacted".to_owned()]
        );
        assert_eq!(interfaces[1].ipv6_count, 1);
        // Non-JSON (e.g. an error line) or a non-array yields no interfaces.
        assert!(parse_ip_json_addr("ip: command not found").is_empty());
        assert!(parse_ip_json_addr("{}").is_empty());
    }

    #[test]
    fn parse_ip_json_route_reads_default_and_cidr() {
        let output = r#"[
          {"dst":"default","gateway":"192.168.0.1","dev":"br0"},
          {"dst":"192.168.0.0/24","dev":"br0","prefsrc":"192.168.0.50"},
          {"dst":"8.8.8.0/24","dev":"wg0"}
        ]"#;
        let routes = parse_ip_json_route(output);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].interface, "br0");
        assert_eq!(routes[1].destination, "192.168.0.0/24");
        // Public destination is redacted while the prefix is preserved.
        assert_eq!(routes[2].destination, "public-redacted/24");
        assert_eq!(routes[2].interface, "wg0");
        assert!(parse_ip_json_route("not json").is_empty());
    }

    fn observed_vm(alias: &str, backend: UtmBackend, nics_json: &str) -> UtmVmObservation {
        UtmVmObservation {
            inventory_alias: Some(alias.to_owned()),
            utm_name: alias.to_owned(),
            bundle_path: format!("/lab/{alias}.utm"),
            backend: Some(backend),
            configuration_version: Some(4),
            power_state: Some("started".to_owned()),
            nics: parse_utm_nics_json(backend, nics_json).unwrap(),
            observation_error: None,
        }
    }

    fn mgmt_shared_profile() -> NetworkProfile {
        parse_network_profile_toml(
            "mgmt_shared_smoke_v1",
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../profiles/vm_lab/network/mgmt_shared_smoke_v1.toml"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn multivm_profile() -> NetworkProfile {
        parse_network_profile_toml(
            "isolated_multivm_v1",
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../profiles/vm_lab/network/isolated_multivm_v1.toml"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn qemu_fixture_modes_parse() {
        for (json, expected) in [
            (QEMU_SHARED_NIC_JSON, AttachmentMode::Shared),
            (QEMU_HOST_ONLY_NIC_JSON, AttachmentMode::HostOnly),
            (QEMU_BRIDGED_EN0_NIC_JSON, AttachmentMode::Bridged),
        ] {
            let nics = parse_utm_nics_json(UtmBackend::Qemu, json).unwrap();
            assert_eq!(nics.len(), 1);
            assert_eq!(nics[0].mode, expected);
        }
    }

    #[test]
    fn apple_fixture_modes_parse() {
        let shared = parse_utm_nics_json(UtmBackend::Apple, APPLE_SHARED_NIC_JSON).unwrap();
        assert_eq!(shared[0].mode, AttachmentMode::Shared);
        assert_eq!(shared[0].mac, "32:6b:39:df:d7:4e");
        let bridged = parse_utm_nics_json(UtmBackend::Apple, APPLE_BRIDGED_NIC_JSON).unwrap();
        assert_eq!(bridged[0].mode, AttachmentMode::Bridged);
        assert_eq!(bridged[0].bridge_interface.as_deref(), Some("en5"));
    }

    #[test]
    fn missing_adapter_fields_fail_closed() {
        let missing_mode = r#"[{"MacAddress": "32:6b:39:df:d7:4e"}]"#;
        assert!(parse_utm_nics_json(UtmBackend::Apple, missing_mode).is_err());
        let missing_mac = r#"[{"Mode": "Shared"}]"#;
        assert!(parse_utm_nics_json(UtmBackend::Apple, missing_mac).is_err());
        let unknown_mode = r#"[{"MacAddress": "32:6b:39:df:d7:4e", "Mode": "Wormhole"}]"#;
        assert!(parse_utm_nics_json(UtmBackend::Apple, unknown_mode).is_err());
        assert!(parse_utm_nics_json(UtmBackend::Apple, "not json").is_err());
    }

    #[test]
    fn bridged_findings_detected() {
        let vms = vec![
            observed_vm("fedora-utm-1", UtmBackend::Qemu, QEMU_BRIDGED_EN0_NIC_JSON),
            observed_vm(
                "windows-utm-1",
                UtmBackend::Qemu,
                QEMU_BRIDGED_UNPINNED_NIC_JSON,
            ),
            observed_vm("debian-headless-2", UtmBackend::Qemu, QEMU_SHARED_NIC_JSON),
        ];
        let findings = detect_attachment_findings(&vms);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "bridged_to_everyday_lan" && f.subject == "fedora-utm-1")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "bridged_interface_unpinned" && f.subject == "windows-utm-1")
        );
        assert!(!findings.iter().any(|f| f.subject == "debian-headless-2"));
    }

    #[test]
    fn duplicate_mac_detected() {
        let vms = vec![
            observed_vm("a", UtmBackend::Qemu, QEMU_SHARED_NIC_JSON),
            observed_vm("b", UtmBackend::Qemu, QEMU_SHARED_NIC_JSON),
        ];
        let findings = detect_attachment_findings(&vms);
        assert!(findings.iter().any(|f| f.kind == "duplicate_mac"));
    }

    #[test]
    fn management_attachment_drift_detected_against_profile() {
        let profile = mgmt_shared_profile();
        let vms = vec![observed_vm(
            "fedora-utm-1",
            UtmBackend::Qemu,
            QEMU_BRIDGED_EN0_NIC_JSON,
        )];
        let findings = detect_profile_drift_findings(&profile, &vms);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "management_attachment_drift")
        );
    }

    #[test]
    fn scenario_nic_missing_yields_not_run() {
        let profile = multivm_profile();
        let vms = vec![observed_vm(
            "debian-headless-2",
            UtmBackend::Qemu,
            QEMU_SHARED_NIC_JSON,
        )];
        let mut findings = detect_profile_drift_findings(&profile, &vms);
        assert!(findings.iter().any(|f| f.kind == "scenario_nic_missing"));
        findings.retain(|f| f.severity != FindingSeverity::Error);
        let (status, _) = overall_status_from_findings(&findings, true);
        assert_eq!(status, NetworkEvidenceStatus::NotRun);
    }

    #[test]
    fn apple_backend_not_supported_for_multivm_profile() {
        let profile = multivm_profile();
        let vms = vec![observed_vm(
            "macos-utm-1",
            UtmBackend::Apple,
            APPLE_SHARED_NIC_JSON,
        )];
        let findings = detect_profile_drift_findings(&profile, &vms);
        assert!(findings.iter().any(|f| f.kind == "backend_not_supported"));
        let (status, _) = overall_status_from_findings(&findings, true);
        assert_eq!(status, NetworkEvidenceStatus::NotSupported);
    }

    #[test]
    fn extra_adapter_detected_for_management_only_profile() {
        let profile = mgmt_shared_profile();
        let two_nics = r#"[{"MacAddress": "3E:AE:A9:5A:61:82", "Mode": "Shared"},
                           {"MacAddress": "3E:AE:A9:5A:61:99", "Mode": "Shared"}]"#;
        let vms = vec![observed_vm("debian-headless-2", UtmBackend::Qemu, two_nics)];
        let findings = detect_profile_drift_findings(&profile, &vms);
        assert!(findings.iter().any(|f| f.kind == "extra_adapter"));
    }

    #[test]
    fn utmctl_list_parses_names_with_spaces() {
        let output = "UUID                                 Status   Name\n\
                      FDC31AD5-CF13-404E-9D9A-0035999D607A started  debian-headless-2\n\
                      B63440F6-8BFD-4E99-AB79-5465AC323398 stopped  Windows XP Harness\n";
        let vms = parse_utmctl_list(output);
        assert_eq!(vms.len(), 2);
        assert_eq!(
            vms[0],
            ("debian-headless-2".to_owned(), "started".to_owned())
        );
        assert_eq!(
            vms[1],
            ("Windows XP Harness".to_owned(), "stopped".to_owned())
        );
    }

    #[test]
    fn netstat_route_normalization() {
        assert_eq!(
            normalize_route_destination("default").as_deref(),
            Some("default")
        );
        assert_eq!(
            normalize_route_destination("10.230.76/24").as_deref(),
            Some("10.230.76.0/24")
        );
        assert_eq!(
            normalize_route_destination("127").as_deref(),
            Some("127.0.0.0/8")
        );
        assert_eq!(
            normalize_route_destination("192.168.64.4").as_deref(),
            Some("192.168.64.4/32")
        );
        assert_eq!(
            normalize_route_destination("169.254").as_deref(),
            Some("169.254.0.0/16")
        );
        assert_eq!(normalize_route_destination("link#22"), None);
    }

    #[test]
    fn host_vpn_route_collision_detected() {
        let host = HostNetworkObservation {
            routes: vec![
                HostRouteObservation {
                    destination: "100.64.0.0/10".to_owned(),
                    interface: "utun9".to_owned(),
                },
                HostRouteObservation {
                    destination: "172.20.5.0/24".to_owned(),
                    interface: "utun9".to_owned(),
                },
                HostRouteObservation {
                    destination: "192.168.64.0/24".to_owned(),
                    interface: "bridge100".to_owned(),
                },
            ],
            vpn_utun_interfaces: vec!["utun9".to_owned()],
            ..HostNetworkObservation::default()
        };
        let profile = multivm_profile();
        let findings = detect_host_route_findings(&host, Some(&profile));
        let collisions: Vec<&AuditFinding> = findings
            .iter()
            .filter(|f| f.kind == "host_route_collision")
            .collect();
        // mesh via utun9 + site pool via utun9; the Shared bridge route is fine.
        assert_eq!(collisions.len(), 2, "{findings:?}");
        assert!(collisions.iter().all(|f| f.subject == "utun9"));
    }

    #[test]
    fn full_tunnel_vpn_flagged_but_half_routes_not_collisions() {
        let host = HostNetworkObservation {
            routes: vec![
                HostRouteObservation {
                    destination: "0.0.0.0/1".to_owned(),
                    interface: "utun9".to_owned(),
                },
                HostRouteObservation {
                    destination: "128.0.0.0/1".to_owned(),
                    interface: "utun9".to_owned(),
                },
            ],
            vpn_utun_interfaces: vec!["utun9".to_owned()],
            full_tunnel_vpn_suspected: true,
            ..HostNetworkObservation::default()
        };
        let findings = detect_host_route_findings(&host, None);
        assert!(findings.iter().any(|f| f.kind == "host_full_tunnel_vpn"));
        assert!(!findings.iter().any(|f| f.kind == "host_route_collision"));
    }

    #[test]
    fn socks_proxy_blocks_evidence() {
        let host = HostNetworkObservation {
            proxy: HostProxyObservation {
                socks_enabled: true,
                ..HostProxyObservation::default()
            },
            ..HostNetworkObservation::default()
        };
        let findings = detect_host_route_findings(&host, None);
        assert!(
            findings.iter().any(
                |f| f.kind == "host_socks_proxy_active" && f.severity == FindingSeverity::Error
            )
        );
    }

    #[test]
    fn netns_sim_wan_collision_detected() {
        let script = "#!/usr/bin/env bash\nWAN_CIDR=\"100.64.0.0/24\"\nWAN_BASE=\"100.64.0\"\n";
        let declared = parse_netns_sim_wan_cidr(script);
        assert_eq!(declared.as_deref(), Some("100.64.0.0/24"));
        let source = SubstrateSourceObservation {
            script_path: "scripts/vm_lab/netns_internet_sim.sh".to_owned(),
            declared_wan_cidr: declared,
            collides_with_mesh: true,
            error: None,
        };
        let findings = detect_substrate_findings(&[source]);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "netns_transit_mesh_collision"
                    && f.severity == FindingSeverity::Error)
        );
    }

    #[test]
    fn inventory_duplicate_ip_and_stale_group_detected() {
        let mut windows = test_inventory_entry("windows-utm-1", "10.230.76.57");
        windows.network_group = Some("lan-192.168.0.0/24".to_owned());
        windows.last_known_ip = Some("10.230.76.57".to_owned());
        let mut ubuntu = test_inventory_entry("ubuntu-utm-1", "10.230.76.57");
        ubuntu.network_group = Some("lan-10.230.76.0/24".to_owned());
        ubuntu.last_known_ip = Some("10.230.76.57".to_owned());
        let mut clean = test_inventory_entry("debian-headless-2", "192.168.64.4");
        clean.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        clean.last_known_ip = Some("192.168.64.4".to_owned());
        let findings = detect_inventory_findings(&[windows, ubuntu, clean]);
        assert!(findings.iter().any(|f| f.kind == "duplicate_recorded_ip"
            && f.subject.contains("windows-utm-1")
            && f.subject.contains("ubuntu-utm-1")));
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "stale_network_group" && f.subject == "windows-utm-1")
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == "stale_network_group" && f.subject == "debian-headless-2")
        );
    }

    fn collected_guest_on(
        alias: &str,
        iface: &str,
        ipv4: &str,
        gateway: &str,
    ) -> GuestNetworkObservation {
        let raw = format!(
            "2: {iface}    inet {ipv4}/24 brd 0.0.0.0 scope global dynamic {iface}\n\
             __RUSTYNET_NET_AUDIT_SECTION__\n\
             2: {iface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\\    link/ether 3e:ae:a9:5a:61:82 brd ff:ff:ff:ff:ff:ff\n\
             __RUSTYNET_NET_AUDIT_SECTION__\n\
             default via {gateway} dev {iface} proto dhcp src {ipv4} metric 100\n\
             __RUSTYNET_NET_AUDIT_SECTION__\n\
             nameserver {gateway}\n"
        );
        parse_linux_guest_sections(alias, &raw)
    }

    #[test]
    fn offfleet_subnet_flags_mode_compliant_node_on_wrong_l2() {
        // Fleet consensus: two nodes declare the utm-shared .64 plane.
        let mut debian = test_inventory_entry("debian-headless-2", "192.168.64.4");
        debian.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        let mut rocky = test_inventory_entry("rocky-utm-1", "192.168.64.105");
        rocky.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        let mut ubuntu = test_inventory_entry("ubuntu-utm-1", "10.230.76.57");
        ubuntu.network_group = Some("lan-10.230.76.0/24".to_owned());

        // Ubuntu is live on the host's real LAN — mode-compliant Shared, wrong L2.
        let guests = vec![collected_guest_on(
            "ubuntu-utm-1",
            "enp0s1",
            "10.230.76.57",
            "10.230.76.1",
        )];
        let findings = detect_offfleet_subnet_findings(&guests, &[debian, rocky, ubuntu]);
        assert_eq!(findings.len(), 1, "exactly one off-fleet node");
        assert_eq!(findings[0].kind, "off_fleet_subnet");
        assert_eq!(findings[0].severity, FindingSeverity::Error);
        assert_eq!(findings[0].subject, "ubuntu-utm-1");
        assert!(findings[0].detail.contains("192.168.64.0/24"));
    }

    #[test]
    fn offfleet_subnet_passes_node_on_the_fleet_plane() {
        let mut debian = test_inventory_entry("debian-headless-2", "192.168.64.4");
        debian.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        let mut rocky = test_inventory_entry("rocky-utm-1", "192.168.64.105");
        rocky.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        let guests = vec![collected_guest_on(
            "rocky-utm-1",
            "enp0s1",
            "192.168.64.105",
            "192.168.64.1",
        )];
        assert!(detect_offfleet_subnet_findings(&guests, &[debian, rocky]).is_empty());
    }

    #[test]
    fn offfleet_subnet_no_finding_without_fleet_consensus() {
        // Only one node declares a plane -> no authoritative fleet -> nothing flagged.
        let mut ubuntu = test_inventory_entry("ubuntu-utm-1", "10.230.76.57");
        ubuntu.network_group = Some("lan-10.230.76.0/24".to_owned());
        let guests = vec![collected_guest_on(
            "ubuntu-utm-1",
            "enp0s1",
            "10.230.76.57",
            "10.230.76.1",
        )];
        assert!(detect_offfleet_subnet_findings(&guests, &[ubuntu]).is_empty());
    }

    #[test]
    fn offfleet_subnet_uses_underlay_not_mesh_overlay() {
        let mut debian = test_inventory_entry("debian-headless-2", "192.168.64.4");
        debian.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        let mut rocky = test_inventory_entry("rocky-utm-1", "192.168.64.105");
        rocky.network_group = Some("utm-shared-192.168.64.0/24".to_owned());
        // The node carries a mesh-overlay address (100.64/10) plus its real
        // underlay on the fleet plane; the mesh address must be ignored.
        let guest = GuestNetworkObservation {
            alias: "rocky-utm-1".to_owned(),
            status: "collected".to_owned(),
            interfaces: vec![
                GuestInterfaceObservation {
                    name: "rustynet0".to_owned(),
                    mac: None,
                    ipv4: vec!["100.64.0.5/10".to_owned()],
                    ipv6_count: 0,
                    mtu: None,
                },
                GuestInterfaceObservation {
                    name: "enp0s1".to_owned(),
                    mac: None,
                    ipv4: vec!["192.168.64.105/24".to_owned()],
                    ipv6_count: 0,
                    mtu: None,
                },
            ],
            default_route_interface: Some("enp0s1".to_owned()),
            dns_servers: Vec::new(),
            error: None,
        };
        assert!(detect_offfleet_subnet_findings(&[guest], &[debian, rocky]).is_empty());
    }

    #[test]
    fn linux_guest_sections_parse() {
        let raw = "2: enp0s1    inet 192.168.64.4/24 brd 192.168.64.255 scope global dynamic enp0s1\n\
                   2: enp0s1    inet6 fe80::a419:949:1c4a:4d9f/64 scope link\n\
                   __RUSTYNET_NET_AUDIT_SECTION__\n\
                   2: enp0s1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\\    link/ether 3e:ae:a9:5a:61:82 brd ff:ff:ff:ff:ff:ff\n\
                   __RUSTYNET_NET_AUDIT_SECTION__\n\
                   default via 192.168.64.1 dev enp0s1 proto dhcp src 192.168.64.4 metric 100\n\
                   __RUSTYNET_NET_AUDIT_SECTION__\n\
                   nameserver 192.168.64.1\n";
        let guest = parse_linux_guest_sections("debian-headless-2", raw);
        assert_eq!(guest.status, "collected");
        assert_eq!(guest.default_route_interface.as_deref(), Some("enp0s1"));
        assert_eq!(guest.dns_servers, vec!["192.168.64.1".to_owned()]);
        let iface = guest
            .interfaces
            .iter()
            .find(|iface| iface.name == "enp0s1")
            .unwrap();
        assert_eq!(iface.mtu, Some(1500));
        assert_eq!(iface.mac.as_deref(), Some("3e:ae:a9:5a:61:82"));
        assert_eq!(iface.ipv4, vec!["192.168.64.4/24".to_owned()]);
        assert_eq!(iface.ipv6_count, 1);
    }

    #[test]
    fn redaction_keeps_private_and_masks_public() {
        assert_eq!(redact_ip_str("192.168.64.4"), "192.168.64.4");
        assert_eq!(redact_ip_str("10.230.76.57"), "10.230.76.57");
        assert_eq!(redact_ip_str("100.64.0.2"), "100.64.0.2");
        assert_eq!(redact_ip_str("8.8.8.8"), "public-redacted");
        assert_eq!(redact_ip_str("2001:4860:4860::8888"), "public-redacted");
        assert_eq!(
            redact_ip_str("fe80::a419:949:1c4a:4d9f"),
            "fe80::a419:949:1c4a:4d9f"
        );
        assert_eq!(
            redact_ip_str("fd21:69d4:6afd:fa50::1"),
            "fd21:69d4:6afd:fa50::1"
        );
    }

    #[test]
    fn secret_guard_blocks_leaks() {
        let banned = vec!["tempo".to_owned(), "password".to_owned()];
        assert!(ensure_no_secret_values("{\"ok\":true}", &banned).is_ok());
        assert!(ensure_no_secret_values("{\"x\":\"tempo\"}", &banned).is_err());
    }

    #[test]
    fn evidence_write_is_atomic_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("vm_network_evidence.json");
        write_evidence_atomic(&path, "{\"schema_version\":1}").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"schema_version\":1}"
        );
        // No temp residue.
        let residue: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(residue.is_empty());
    }

    #[test]
    fn scutil_proxy_parses() {
        let output = "<dictionary> {\n  SOCKSEnable : 1\n  HTTPEnable : 0\n}\n";
        let proxy = parse_scutil_proxy(output);
        assert!(proxy.socks_enabled);
        assert!(!proxy.http_enabled);
    }

    fn test_inventory_entry(alias: &str, ssh_target: &str) -> VmInventoryEntry {
        VmInventoryEntry {
            alias: alias.to_owned(),
            ssh_target: ssh_target.to_owned(),
            ssh_user: Some("lab".to_owned()),
            ssh_password: None,
            include_in_all: None,
            os: Some("Debian/Linux".to_owned()),
            last_known_ip: None,
            parent_device: None,
            last_known_network: None,
            network_group: None,
            node_id: None,
            lab_role: None,
            mesh_ip: None,
            exit_capable: None,
            relay_capable: None,
            remote_temp_dir: None,
            utm_staging_dir: None,
            rustynet_src_dir: None,
            platform: None,
            remote_shell: None,
            guest_exec_mode: None,
            service_manager: None,
            controller: None,
        }
    }
}
