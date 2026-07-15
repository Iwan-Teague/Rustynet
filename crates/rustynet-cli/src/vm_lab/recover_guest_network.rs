//! `ops vm-lab-recover-guest-network`: recover a UTM/vmnet lab guest that has
//! lost its IPv4 lease (e.g. a NIC MAC regen leaves a netplan `match:
//! macaddress:` pin stale, so the interface goes unmanaged and no DHCP client
//! runs). Such a guest has no IPv4 and often no qemu-guest-agent, so every
//! SSH-over-IPv4 / `utmctl exec` path is locked out.
//!
//! A vmnet guest with no IPv4 still has an RFC-4291 link-local `fe80::` address
//! on the same L2 as the host bridge. This command reads that address from the
//! host neighbor cache (or derives it from the NIC MAC), SSHes to it over IPv6
//! with a zone id, and applies a distro-aware DHCP-config repair (netplan
//! name-match / NetworkManager / systemd-networkd), then reports and optionally
//! records the recovered IPv4.
//!
//! Proven-by-hand and specified in
//! `documents/operations/active/LiveLabFindings_2026-07-12.md`
//! (section "2026-07-14 (cont.) — Ubuntu `.64` IP RESOLVED").
//!
//! macOS note: this MUST be run from a real shell. The Claude/MCP servers are
//! sandboxed under macOS Local Network Privacy and cannot open the link-local
//! socket; only the unsandboxed shell reaches the guest.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{VmController, VmInventoryEntry};

const RECOVER_SSH_CONNECT_TIMEOUT_SECS: u64 = 10;
const IPV4_POLL_TIMEOUT_SECS: u64 = 15;
const GUEST_PROBE_SENTINEL: &str = "===RN-NETCFG===";
const GUEST_NETPLAN_SENTINEL: &str = "===RN-NETPLAN===";

/// Configuration for `ops vm-lab-recover-guest-network`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabRecoverGuestNetworkConfig {
    /// Inventory alias of the guest to recover (`--vm`).
    pub vm_alias: String,
    /// Inventory path (`--inventory`); defaults to the repo inventory.
    pub inventory_path: Option<PathBuf>,
    /// Explicit NIC MAC (`--mac`); otherwise read from the UTM bundle plist.
    pub mac: Option<String>,
    /// SSH identity (`--ssh-identity-file`); defaults to the lab key.
    pub ssh_identity_file: Option<PathBuf>,
    /// Persist the recovered IPv4 back into the inventory (`--update-inventory`).
    pub update_inventory: bool,
    /// Resolve + print the plan without touching the guest (`--dry-run`).
    pub dry_run: bool,
}

/// A resolved link-local SSH target: `fe80::…` plus its host zone (`bridgeN`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkLocalTarget {
    pub address: String,
    pub zone: String,
}

impl LinkLocalTarget {
    fn scoped(&self) -> String {
        format!("{}%{}", self.address, self.zone)
    }
}

/// Which network-config system the guest uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestNetConfig {
    Netplan,
    NetworkManager,
    SystemdNetworkd,
    Unknown,
}

impl GuestNetConfig {
    fn label(self) -> &'static str {
        match self {
            GuestNetConfig::Netplan => "netplan",
            GuestNetConfig::NetworkManager => "NetworkManager",
            GuestNetConfig::SystemdNetworkd => "systemd-networkd",
            GuestNetConfig::Unknown => "unknown",
        }
    }
}

struct GuestNetInfo {
    interface: String,
    config: GuestNetConfig,
    /// Confirmed root cause, when detectable (e.g. a stale netplan MAC pin).
    root_cause: Option<String>,
}

// --- Pure logic (unit-tested; no live guest required) ---

/// Derive the RFC-4291 modified-EUI-64 link-local address from a NIC MAC:
/// flip the U/L bit of the first octet, insert `ff:fe` in the middle.
pub(crate) fn derive_link_local_from_mac(mac: &str) -> Option<String> {
    let normalized = super::normalize_mac_address(mac)?;
    let octets = normalized
        .split(':')
        .map(|hex| u8::from_str_radix(hex, 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    if octets.len() != 6 {
        return None;
    }
    let eui = [
        octets[0] ^ 0x02,
        octets[1],
        octets[2],
        0xff,
        0xfe,
        octets[3],
        octets[4],
        octets[5],
    ];
    let addr = Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        (u16::from(eui[0]) << 8) | u16::from(eui[1]),
        (u16::from(eui[2]) << 8) | u16::from(eui[3]),
        (u16::from(eui[4]) << 8) | u16::from(eui[5]),
        (u16::from(eui[6]) << 8) | u16::from(eui[7]),
    );
    Some(addr.to_string())
}

/// Find the guest's link-local address + host zone in `ndp -an` output by MAC.
/// Rows look like `fe80::…%bridge100  1a:e6:…  bridge100 permanent R`. Skips
/// header/IPv4/malformed rows; returns `None` if the MAC is absent.
pub(crate) fn find_link_local_by_mac(ndp_output: &str, mac: &str) -> Option<LinkLocalTarget> {
    let target_mac = super::normalize_mac_address(mac)?;
    for line in ndp_output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(neighbor), Some(row_mac)) = (cols.first().copied(), cols.get(1).copied()) else {
            continue;
        };
        if super::normalize_mac_address(row_mac).as_deref() != Some(target_mac.as_str()) {
            continue;
        }
        // Prefer the `%zone` scope in the Neighbor column; fall back to the
        // Netif column (index 2) for ndp variants that omit it, so a reachable
        // guest is not falsely reported as not-found.
        let (address, zone) = match neighbor.split_once('%') {
            Some((address, zone)) => (address, zone),
            None => match cols.get(2).copied() {
                Some(netif) => (neighbor, netif),
                None => continue,
            },
        };
        if !address.to_ascii_lowercase().starts_with("fe80:") {
            continue;
        }
        if !is_safe_interface_name(zone) {
            continue;
        }
        return Some(LinkLocalTarget {
            address: address.to_owned(),
            zone: zone.to_owned(),
        });
    }
    None
}

/// Extract the NIC MAC from a UTM bundle `config.plist` (XML). Text-scan rather
/// than a plist dependency — the schema is simple and stable.
pub(crate) fn parse_nic_mac_from_config_plist(contents: &str) -> Option<String> {
    let key_pos = contents.find("<key>MacAddress</key>")?;
    let after_key = &contents[key_pos + "<key>MacAddress</key>".len()..];
    let string_start = after_key.find("<string>")? + "<string>".len();
    let string_end = after_key[string_start..].find("</string>")?;
    super::normalize_mac_address(after_key[string_start..string_start + string_end].trim())
}

/// Pick the primary ethernet interface from `ip -o link show`: the first
/// non-loopback, non-virtual link.
pub(crate) fn pick_primary_interface(ip_link_output: &str) -> Option<String> {
    for line in ip_link_output.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(index), Some(name_raw), Some(_rest)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if index.trim().parse::<u32>().is_err() {
            continue;
        }
        let name = name_raw.trim();
        let name = name.split('@').next().unwrap_or(name);
        if name.is_empty() || is_virtual_interface(name) || !is_safe_interface_name(name) {
            continue;
        }
        return Some(name.to_owned());
    }
    None
}

fn is_virtual_interface(name: &str) -> bool {
    const VIRTUAL_PREFIXES: &[&str] = &[
        "lo", "docker", "veth", "br-", "virbr", "wg", "tun", "tap", "vnet", "bond", "dummy", "gre",
        "sit", "vxlan", "vlan", "kube", "cni", "flannel", "cali",
    ];
    VIRTUAL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn is_safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn is_safe_ssh_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The canonical name-matched DHCP netplan for `interface` — no MAC pin, so it
/// survives future MAC regens. This is exactly the fix proven by hand.
pub(crate) fn corrected_netplan_yaml(interface: &str) -> String {
    format!(
        "network:\n  version: 2\n  ethernets:\n    {interface}:\n      dhcp4: true\n      dhcp6: true\n"
    )
}

/// Whether a netplan document pins a NIC by MAC (the stale-pin failure mode).
pub(crate) fn netplan_yaml_pins_mac(contents: &str) -> bool {
    contents.to_ascii_lowercase().contains("macaddress")
}

/// Extract the IPv4 address for `interface` from `ip -4 -o addr show` output.
pub(crate) fn parse_ipv4_for_interface(ip_addr_output: &str, interface: &str) -> Option<String> {
    for line in ip_addr_output.lines() {
        let mut cols = line.split_whitespace();
        let (Some(_index), Some(name), Some(keyword), Some(cidr)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if name != interface || keyword != "inet" {
            continue;
        }
        let addr = cidr.split('/').next().unwrap_or(cidr);
        if addr.parse::<Ipv4Addr>().is_ok() {
            return Some(addr.to_owned());
        }
    }
    None
}

fn netplan_repair_script(interface: &str) -> String {
    const TEMPLATE: &str = r#"set -eu
ts="$(date +%Y%m%dT%H%M%S)"
mkdir -p /etc/netplan
for f in /etc/netplan/*.yaml; do
  [ -e "$f" ] || continue
  cp -a "$f" "$f.rustynet-recover.$ts.bak"
  case "$f" in
    /etc/netplan/00-rustynet-recovery.yaml) ;;
    *) mv "$f" "$f.rustynet-disabled.$ts" ;;
  esac
done
cat > /etc/netplan/00-rustynet-recovery.yaml <<'RN_NETPLAN_EOF'
__RN_NETPLAN__RN_NETPLAN_EOF
chmod 600 /etc/netplan/00-rustynet-recovery.yaml
netplan apply
"#;
    TEMPLATE.replace("__RN_NETPLAN__", &corrected_netplan_yaml(interface))
}

fn network_manager_repair_script(interface: &str) -> String {
    const TEMPLATE: &str = r#"set -eu
iface="__RN_IFACE__"
con="$(nmcli -t -f NAME,DEVICE con show 2>/dev/null | awk -F: -v i="$iface" '$2==i{print $1; exit}')"
if [ -n "${con:-}" ]; then
  nmcli con mod "$con" 802-3-ethernet.mac-address "" 2>/dev/null || true
  nmcli con mod "$con" ipv4.method auto ipv6.method auto || true
  nmcli con up "$con"
else
  nmcli con add type ethernet ifname "$iface" con-name "rustynet-recover-$iface" ipv4.method auto ipv6.method auto
  nmcli con up "rustynet-recover-$iface"
fi
"#;
    TEMPLATE.replace("__RN_IFACE__", interface)
}

fn networkd_repair_script(interface: &str) -> String {
    const TEMPLATE: &str = r#"set -eu
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/10-rustynet-recover.network <<'RN_NETWORKD_EOF'
[Match]
Name=__RN_IFACE__
[Network]
DHCP=yes
RN_NETWORKD_EOF
chmod 644 /etc/systemd/network/10-rustynet-recover.network
systemctl enable --now systemd-networkd 2>/dev/null || true
networkctl reload
networkctl reconfigure "__RN_IFACE__"
"#;
    TEMPLATE.replace("__RN_IFACE__", interface)
}

// --- Live orchestration (argv-only exec; fail closed) ---

fn run_capture(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program} invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{program} produced non-UTF-8 output"))
}

/// Best-effort ICMPv6 echo to warm the neighbor cache. macOS 14+ folded `ping6`
/// into `ping -6`; try `ping6` first, then fall back.
fn ping6_once(scoped: &str) {
    if Command::new("ping6")
        .args(["-c", "1", scoped])
        .output()
        .is_ok()
    {
        return;
    }
    let _ = Command::new("ping")
        .args(["-6", "-c", "1", scoped])
        .output();
}

/// Active `bridge*` interfaces on the host (`ifconfig -l`).
fn host_bridges() -> Vec<String> {
    let Ok(list) = run_capture("ifconfig", &["-l"]) else {
        return Vec::new();
    };
    list.split_whitespace()
        .filter(|name| name.starts_with("bridge"))
        .map(str::to_owned)
        .collect()
}

fn ssh_common_args(identity: &str, ssh_target: &str) -> Vec<String> {
    // Recovery reaches a possibly-reinstalled guest over the host-local
    // link-local L2, where the guest host key may have changed after a rebuild
    // and the path is host-adjacent. Host-key pinning is intentionally disabled
    // for this recovery-only tool; it is never used for ordinary orchestration.
    vec![
        "-6".to_owned(),
        "-i".to_owned(),
        identity.to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=no".to_owned(),
        "-o".to_owned(),
        "UserKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        format!("ConnectTimeout={RECOVER_SSH_CONNECT_TIMEOUT_SECS}"),
        ssh_target.to_owned(),
    ]
}

fn run_ssh_capture(
    identity: &str,
    ssh_target: &str,
    remote_command: &str,
) -> Result<String, String> {
    let mut args = ssh_common_args(identity, ssh_target);
    args.push(remote_command.to_owned());
    let output = Command::new("ssh")
        .args(args.iter().map(String::as_str))
        .output()
        .map_err(|err| format!("ssh invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "ssh to {ssh_target} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "ssh produced non-UTF-8 output".to_owned())
}

/// Pipe a repair script to `sudo bash -s` on the guest over link-local SSH.
/// The script is a fixed template with only a validated interface name
/// substituted, and is passed on stdin — never assembled into a shell string.
fn run_ssh_script_with_sudo(identity: &str, ssh_target: &str, script: &str) -> Result<(), String> {
    let mut args = ssh_common_args(identity, ssh_target);
    args.push("sudo".to_owned());
    args.push("bash".to_owned());
    args.push("-s".to_owned());
    let mut child = Command::new("ssh")
        .args(args.iter().map(String::as_str))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("ssh invocation failed: {err}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open ssh stdin".to_owned())?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|err| format!("write repair script to ssh stdin failed: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("await ssh repair failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "guest DHCP repair over ssh failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn resolve_mac(
    config: &VmLabRecoverGuestNetworkConfig,
    entry: &VmInventoryEntry,
) -> Result<String, String> {
    if let Some(mac) = config.mac.as_deref() {
        return super::normalize_mac_address(mac)
            .ok_or_else(|| format!("--mac {mac:?} is not a valid MAC address"));
    }
    if let Some(VmController::LocalUtm { bundle_path, .. }) = entry.controller.as_ref() {
        let plist = bundle_path.join("config.plist");
        let contents = std::fs::read_to_string(&plist)
            .map_err(|err| format!("read {} failed: {err}", plist.display()))?;
        return parse_nic_mac_from_config_plist(&contents)
            .ok_or_else(|| format!("no MacAddress found in {}", plist.display()));
    }
    Err(format!(
        "cannot resolve a NIC MAC for {}: pass --mac <aa:bb:..> or give the inventory entry a local_utm controller with a bundle_path",
        entry.alias
    ))
}

fn resolve_link_local_target(
    mac: &str,
    dry_run: bool,
) -> Result<(LinkLocalTarget, String), String> {
    let ndp = run_capture("ndp", &["-an"]).unwrap_or_default();
    if let Some(target) = find_link_local_by_mac(&ndp, mac) {
        return Ok((target, "resolved from ndp neighbor cache".to_owned()));
    }
    let derived = derive_link_local_from_mac(mac)
        .ok_or_else(|| format!("cannot derive a link-local address from MAC {mac}"))?;
    if dry_run {
        // Dry-run stays read-only: do not ping to warm the cache. Report the
        // derived address against the first active bridge as a best-effort zone.
        let zone = host_bridges().into_iter().next().ok_or_else(|| {
            "no active bridge* interface found on the host to scope the link-local address"
                .to_owned()
        })?;
        return Ok((
            LinkLocalTarget {
                address: derived,
                zone,
            },
            "derived from MAC (unconfirmed; not in ndp cache)".to_owned(),
        ));
    }
    for bridge in host_bridges() {
        ping6_once(&format!("{derived}%{bridge}"));
        let ndp = run_capture("ndp", &["-an"]).unwrap_or_default();
        if let Some(target) = find_link_local_by_mac(&ndp, mac) {
            return Ok((target, format!("confirmed via ping6 on {bridge}")));
        }
    }
    Err(format!(
        "could not resolve a link-local address for MAC {mac}: not present in ndp and no host bridge responded (is the guest powered on and on the vmnet L2?)"
    ))
}

fn ssh_query_guest(identity: &str, ssh_target: &str) -> Result<GuestNetInfo, String> {
    let probe = format!(
        "ip -o link show; echo '{GUEST_PROBE_SENTINEL}'; \
         [ -d /etc/netplan ] && echo netplan; \
         command -v nmcli >/dev/null 2>&1 && echo nmcli; \
         command -v networkctl >/dev/null 2>&1 && echo networkd; \
         echo '{GUEST_NETPLAN_SENTINEL}'; cat /etc/netplan/*.yaml 2>/dev/null || true"
    );
    let out = run_ssh_capture(identity, ssh_target, &probe)?;
    let (links, rest) = out
        .split_once(GUEST_PROBE_SENTINEL)
        .ok_or_else(|| "guest network probe returned unexpected output".to_owned())?;
    let (caps, netplan_contents) = rest
        .split_once(GUEST_NETPLAN_SENTINEL)
        .unwrap_or((rest, ""));
    let interface = pick_primary_interface(links)
        .ok_or_else(|| "could not identify a primary ethernet interface on the guest".to_owned())?;
    let config = if caps.contains("netplan") {
        GuestNetConfig::Netplan
    } else if caps.contains("nmcli") {
        GuestNetConfig::NetworkManager
    } else if caps.contains("networkd") {
        GuestNetConfig::SystemdNetworkd
    } else {
        GuestNetConfig::Unknown
    };
    let root_cause = if config == GuestNetConfig::Netplan && netplan_yaml_pins_mac(netplan_contents)
    {
        Some(
            "netplan pins the NIC by MAC (goes unmanaged after a MAC regen) — the documented failure mode"
                .to_owned(),
        )
    } else {
        None
    };
    Ok(GuestNetInfo {
        interface,
        config,
        root_cause,
    })
}

fn apply_guest_repair(
    identity: &str,
    ssh_target: &str,
    guest: &GuestNetInfo,
) -> Result<(), String> {
    let script = match guest.config {
        GuestNetConfig::Netplan => netplan_repair_script(&guest.interface),
        GuestNetConfig::NetworkManager => network_manager_repair_script(&guest.interface),
        GuestNetConfig::SystemdNetworkd => networkd_repair_script(&guest.interface),
        GuestNetConfig::Unknown => {
            return Err(
                "guest has no recognized network config system (netplan / NetworkManager / systemd-networkd)"
                    .to_owned(),
            );
        }
    };
    run_ssh_script_with_sudo(identity, ssh_target, &script)
}

fn poll_recovered_ipv4(
    identity: &str,
    ssh_target: &str,
    interface: &str,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(IPV4_POLL_TIMEOUT_SECS);
    loop {
        if let Ok(out) = run_ssh_capture(identity, ssh_target, "ip -4 -o addr show")
            && let Some(ip) = parse_ipv4_for_interface(&out, interface)
        {
            return Ok(ip);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no IPv4 appeared on {interface} within {IPV4_POLL_TIMEOUT_SECS}s after the repair"
            ));
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// `ops vm-lab-recover-guest-network`.
pub fn execute_ops_vm_lab_recover_guest_network(
    config: VmLabRecoverGuestNetworkConfig,
) -> Result<String, String> {
    let inventory_path = config
        .inventory_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(super::DEFAULT_VM_LAB_INVENTORY_PATH));
    let inventory = super::load_inventory(inventory_path.as_path())?;
    let entry = inventory
        .iter()
        .find(|entry| entry.alias == config.vm_alias)
        .ok_or_else(|| {
            format!(
                "vm-lab-recover-guest-network: alias {} not found in inventory {}",
                config.vm_alias,
                inventory_path.display()
            )
        })?;

    let ssh_user = entry
        .ssh_user
        .clone()
        .ok_or_else(|| format!("inventory entry {} has no ssh_user", config.vm_alias))?;
    if !is_safe_ssh_user(&ssh_user) {
        return Err(format!(
            "inventory ssh_user {ssh_user:?} contains unsafe characters"
        ));
    }
    let identity = config
        .ssh_identity_file
        .clone()
        .unwrap_or_else(super::default_lab_ssh_identity_path);
    let identity_str = identity
        .to_str()
        .ok_or_else(|| "ssh identity path is not valid UTF-8".to_owned())?
        .to_owned();

    let mac = resolve_mac(&config, entry)?;
    let (target, resolution) = resolve_link_local_target(&mac, config.dry_run)?;
    if target.address.parse::<Ipv6Addr>().is_err() || !is_safe_interface_name(&target.zone) {
        return Err(format!(
            "resolved an invalid link-local target {}%{}",
            target.address, target.zone
        ));
    }
    let scoped = target.scoped();
    let ssh_target = format!("{ssh_user}@{scoped}");

    let mut report = String::new();
    report.push_str(&format!("vm={} mac={mac}\n", config.vm_alias));
    report.push_str(&format!("link_local={scoped} ({resolution})\n"));

    if config.dry_run {
        report.push_str(&format!(
            "DRY-RUN: would `ssh -6 -i {identity_str} {ssh_target}` and apply a distro-aware DHCP repair.\n\
             No guest mutation performed. Run from a real shell on macOS (the MCP servers are LNP-sandboxed and cannot open the link-local socket).\n"
        ));
        return Ok(report);
    }

    let guest = ssh_query_guest(&identity_str, &ssh_target)?;
    report.push_str(&format!(
        "interface={} config_system={}\n",
        guest.interface,
        guest.config.label()
    ));
    if let Some(root_cause) = &guest.root_cause {
        report.push_str(&format!("root_cause={root_cause}\n"));
    }

    apply_guest_repair(&identity_str, &ssh_target, &guest)?;
    report.push_str("DHCP repair applied; polling for IPv4...\n");

    let ipv4 = poll_recovered_ipv4(&identity_str, &ssh_target, &guest.interface)?;
    report.push_str(&format!("recovered_ipv4={ipv4} on {}\n", guest.interface));

    if config.update_inventory {
        let mut updates: BTreeMap<&str, &str> = BTreeMap::new();
        updates.insert(config.vm_alias.as_str(), ipv4.as_str());
        let message = super::write_inventory_live_ips(inventory_path.as_path(), &updates)?;
        report.push_str(&format!("{message}\n"));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_link_local_matches_reference_vector() {
        assert_eq!(
            derive_link_local_from_mac("1a:e6:25:c2:a7:c1").as_deref(),
            Some("fe80::18e6:25ff:fec2:a7c1")
        );
        // Case/format-insensitive via normalize.
        assert_eq!(
            derive_link_local_from_mac("1A:E6:25:C2:A7:C1").as_deref(),
            Some("fe80::18e6:25ff:fec2:a7c1")
        );
        assert!(derive_link_local_from_mac("not-a-mac").is_none());
        assert!(derive_link_local_from_mac("1a:e6:25:c2:a7").is_none());
    }

    #[test]
    fn find_link_local_by_mac_parses_and_negatives() {
        let ndp = "\
Neighbor                             Linklayer Address  Netif Expire    S Flags
fe80::18e6:25ff:fec2:a7c1%bridge100  1a:e6:25:c2:a7:c1  bridge100 permanent R
192.168.64.1                         88:66:5a:11:22:33  bridge100 23h59m59s S
";
        let found = find_link_local_by_mac(ndp, "1a:e6:25:c2:a7:c1").expect("should find");
        assert_eq!(found.address, "fe80::18e6:25ff:fec2:a7c1");
        assert_eq!(found.zone, "bridge100");
        assert_eq!(found.scoped(), "fe80::18e6:25ff:fec2:a7c1%bridge100");
        // A MAC not in the cache → None (the caller then derives + pings).
        assert!(find_link_local_by_mac(ndp, "aa:bb:cc:dd:ee:ff").is_none());
        // The IPv4 row has no %zone → never matched as link-local.
        assert!(find_link_local_by_mac(ndp, "88:66:5a:11:22:33").is_none());
        // A variant that omits %zone in the Neighbor column → zone from Netif.
        let ndp_no_zone = "fe80::18e6:25ff:fec2:a7c1  1a:e6:25:c2:a7:c1  bridge100 permanent R\n";
        let found2 = find_link_local_by_mac(ndp_no_zone, "1a:e6:25:c2:a7:c1")
            .expect("should fall back to the Netif column for the zone");
        assert_eq!(found2.address, "fe80::18e6:25ff:fec2:a7c1");
        assert_eq!(found2.zone, "bridge100");
    }

    #[test]
    fn parse_nic_mac_from_config_plist_reads_and_normalizes() {
        let plist = "\
<?xml version=\"1.0\"?>
<plist version=\"1.0\">
<dict>
  <key>Backend</key>
  <string>QEMU</string>
  <key>MacAddress</key>
  <string>1A:E6:25:C2:A7:C1</string>
</dict>
</plist>
";
        assert_eq!(
            parse_nic_mac_from_config_plist(plist).as_deref(),
            Some("1a:e6:25:c2:a7:c1")
        );
        assert!(parse_nic_mac_from_config_plist("<dict></dict>").is_none());
    }

    #[test]
    fn pick_primary_interface_skips_lo_and_virtual() {
        let ip_link = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\\    link/ether 1a:e6:25:c2:a7:c1 brd ff:ff:ff:ff:ff:ff
3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none
";
        assert_eq!(pick_primary_interface(ip_link).as_deref(), Some("enp0s1"));
        assert!(pick_primary_interface("garbage\nlines\n").is_none());
    }

    #[test]
    fn netplan_transform_drops_mac_pin_and_enables_dhcp() {
        let stale = "\
network:
  version: 2
  ethernets:
    enp0s1:
      match: { macaddress: a2:dc:f9:9b:0c:8a }
      set-name: enp0s1
      dhcp4: true
";
        assert!(netplan_yaml_pins_mac(stale));
        let corrected = corrected_netplan_yaml("enp0s1");
        assert!(!netplan_yaml_pins_mac(&corrected));
        assert!(corrected.contains("enp0s1:"));
        assert!(corrected.contains("dhcp4: true"));
        assert!(corrected.contains("dhcp6: true"));
        assert!(!corrected.contains("match:"));
        assert!(!corrected.contains("set-name:"));
        // The generated repair script embeds the corrected config, name-matched.
        let script = netplan_repair_script("enp0s1");
        assert!(script.contains("netplan apply"));
        assert!(script.contains("dhcp4: true"));
        assert!(!netplan_yaml_pins_mac(&script));
    }

    #[test]
    fn parse_ipv4_for_interface_extracts_dhcp_lease() {
        let ip_addr = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: enp0s1    inet 192.168.64.21/24 brd 192.168.64.255 scope global dynamic enp0s1\\       valid_lft 86390sec preferred_lft 86390sec
";
        assert_eq!(
            parse_ipv4_for_interface(ip_addr, "enp0s1").as_deref(),
            Some("192.168.64.21")
        );
        assert!(parse_ipv4_for_interface(ip_addr, "eth9").is_none());
    }

    #[test]
    fn interface_and_user_safety_rejects_injection() {
        assert!(is_safe_interface_name("enp0s1"));
        assert!(is_safe_interface_name("bridge100"));
        assert!(!is_safe_interface_name("en p0"));
        assert!(!is_safe_interface_name("a;rm -rf"));
        assert!(!is_safe_interface_name(""));
        assert!(is_safe_ssh_user("ubuntu"));
        assert!(!is_safe_ssh_user("root;evil"));
    }
}
