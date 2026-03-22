#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::env;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};

const RUSTYNET_STATE_DIR: &str = "/var/lib/rustynet";
const RUSTYNET_CONFIG_DIR: &str = "/etc/rustynet";
const RUSTYNET_RUN_DIR: &str = "/run/rustynet";

const ASSIGNMENT_BUNDLE: &str = "/var/lib/rustynet/rustynetd.assignment";
const TRAVERSAL_BUNDLE: &str = "/var/lib/rustynet/rustynetd.traversal";
const MEMBERSHIP_SNAPSHOT: &str = "/var/lib/rustynet/membership.snapshot";
const MEMBERSHIP_LOG: &str = "/var/lib/rustynet/membership.log";
const DNS_ZONE_BUNDLE: &str = "/var/lib/rustynet/rustynetd.dns-zone";
const TRUST_EVIDENCE: &str = "/var/lib/rustynet/rustynetd.trust";
const WG_PUBLIC_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";

const ASSIGNMENT_PUB_KEY: &str = "/etc/rustynet/assignment.pub";
const TRAVERSAL_PUB_KEY: &str = "/etc/rustynet/traversal.pub";
const TRUST_PUB_KEY: &str = "/etc/rustynet/trust-evidence.pub";
const DNS_ZONE_PUB_KEY: &str = "/etc/rustynet/dns-zone.pub";

const DEFAULT_WG_PORT: &str = "51820";

#[derive(Debug, Default)]
struct Config {
    output_path: Option<PathBuf>,
    wg_iface: Option<String>,
    wg_port_override: Option<String>,
    node_id_override: Option<String>,
    quiet: bool,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let config = parse_args().map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;

    let require = |name: &str| {
        require_cmd(name).map_err(|err| {
            eprintln!("[collect-discovery] ERROR: {err}");
            1
        })
    };

    require("ip")?;
    require("hostname")?;
    require("uname")?;

    let wg_available = command_exists("wg");
    let jq_available = command_exists("jq");
    let curl_available = command_exists("curl");
    let wget_available = command_exists("wget");

    if !wg_available {
        log(
            config.quiet,
            "WARNING: 'wg' (wireguard-tools) not found - WireGuard fields will be empty.",
        );
    }

    let host_name = hostname_value().map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let os_name = run_capture("uname", &["-s"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let os_release = os_release_value();
    let kernel = run_capture("uname", &["-r"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let arch = run_capture("uname", &["-m"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let collected_at_unix = run_capture("date", &["-u", "+%s"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let collected_at_iso = run_capture("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;

    log(config.quiet, "Resolving Rustynet node identity...");
    let node_id = resolve_node_id(&config, &host_name);

    log(config.quiet, "Detecting WireGuard interface...");
    let wg_iface = config
        .wg_iface
        .clone()
        .or_else(|| detect_wg_interface(wg_available))
        .unwrap_or_default();
    if wg_iface.is_empty() {
        log(
            config.quiet,
            "WARNING: No WireGuard interface found. WireGuard fields will be empty.",
        );
    }

    log(config.quiet, "Reading WireGuard configuration...");
    let mut wg_public_key = read_trimmed_file(WG_PUBLIC_KEY_PATH).unwrap_or_default();
    if !wg_public_key.is_empty() {
        log(
            config.quiet,
            &format!("Public key read from {WG_PUBLIC_KEY_PATH}"),
        );
    }

    let mut wg_listen_port = String::new();
    let mut wg_iface_addresses = String::new();
    if !wg_iface.is_empty() && wg_available {
        if let Some(wg_show_output) = read_wg_show(&wg_iface) {
            if wg_public_key.is_empty() {
                wg_public_key = parse_public_key_from_wg_show(&wg_show_output);
            }
            wg_listen_port = parse_listen_port_from_wg_show(&wg_show_output);
        }
        wg_iface_addresses = ip_interface_addresses(&wg_iface)?;
    }

    if let Some(override_port) = &config.wg_port_override {
        wg_listen_port = override_port.clone();
    } else if wg_listen_port.is_empty() {
        wg_listen_port = DEFAULT_WG_PORT.to_string();
    }

    log(
        config.quiet,
        "Collecting local interface addresses (host candidates)...",
    );
    let host_candidates_raw = collect_host_candidates(&wg_iface)?;

    log(config.quiet, "Detecting public/reflexive IP address...");
    let public_ip = if curl_available || wget_available {
        let detected = detect_public_ip(curl_available, wget_available);
        if let Some(value) = &detected {
            log(config.quiet, &format!("Detected public IP: {value}"));
        } else {
            log(
                config.quiet,
                "WARNING: Could not detect public IP. Server-reflexive candidate will be empty.",
            );
        }
        detected.unwrap_or_default()
    } else {
        log(
            config.quiet,
            "WARNING: Neither curl nor wget available. Skipping public IP detection.",
        );
        String::new()
    };

    log(config.quiet, "Gathering NAT profile hints...");
    let first_lan_ip = host_candidates_raw
        .lines()
        .next()
        .and_then(|line| line.split(':').next())
        .unwrap_or_default()
        .to_string();
    let behind_nat = !public_ip.is_empty() && !first_lan_ip.is_empty() && public_ip != first_lan_ip;
    let port_forwarded_hint = if behind_nat {
        "assumed_no - node is behind NAT; manual port-forward or relay may be required"
    } else {
        "likely_yes - public IP matches local IP (no NAT detected)"
    };

    log(config.quiet, "Collecting existing WireGuard peer list...");
    let wg_peers_json = collect_wg_peers(&wg_iface, wg_available)?;

    log(config.quiet, "Inventorying Rustynet signed artifacts...");
    let assignment_pub_key_b64 = read_verifier_key_b64(ASSIGNMENT_PUB_KEY).unwrap_or_default();
    let traversal_pub_key_b64 = read_verifier_key_b64(TRAVERSAL_PUB_KEY).unwrap_or_default();
    let dns_zone_pub_key_b64 = read_verifier_key_b64(DNS_ZONE_PUB_KEY).unwrap_or_default();
    let trust_pub_key_b64 = read_verifier_key_b64(TRUST_PUB_KEY).unwrap_or_default();

    log(config.quiet, "Checking rustynetd service status...");
    let daemon_status = daemon_status(RUSTYNET_RUN_DIR)?;

    log(config.quiet, "Building discovery bundle...");
    let endpoint_candidates =
        build_endpoint_candidates(&host_candidates_raw, &wg_listen_port, &public_ip);
    let peer_stanza_template = build_peer_stanza_template(
        &node_id,
        &host_name,
        &wg_public_key,
        &public_ip,
        &first_lan_ip,
        &wg_listen_port,
    );

    let discovery = json!({
        "schema_version": 1,
        "collected_at_unix": parse_u64(&collected_at_unix, "collected_at_unix")?,
        "collected_at_iso": collected_at_iso,
        "purpose": "cross_network_discovery_bundle",
        "note": "Share this bundle with the remote network administrator. They need the node_identity, wireguard, endpoint_candidates, and verifier_keys sections to configure a signed traversal/assignment bundle pointing at this node.",
        "node_identity": {
            "node_id": node_id,
            "hostname": host_name,
            "os": format!("{os_name} {os_release}"),
            "kernel": kernel,
            "arch": arch,
        },
        "wireguard": {
            "interface": wg_iface,
            "public_key": wg_public_key,
            "listen_port": parse_u64(&wg_listen_port, "wireguard.listen_port")?,
            "interface_addresses": wg_iface_addresses,
            "peer_stanza_template": peer_stanza_template,
        },
        "endpoint_candidates": endpoint_candidates,
        "nat_profile": {
            "behind_nat": behind_nat,
            "first_lan_ip": first_lan_ip,
            "detected_public_ip": public_ip,
            "port_forwarded_hint": port_forwarded_hint,
            "recommended_traversal_strategy": if behind_nat {
                "hole_punch_or_relay - node is behind NAT; provision relay candidate in traversal bundle"
            } else {
                "direct - use server_reflexive or host candidate"
            },
        },
        "verifier_keys": {
            "note": "Remote network must trust these public keys to verify signed bundles originating from this network.",
            "assignment_verifier_key_b64": assignment_pub_key_b64,
            "traversal_verifier_key_b64": traversal_pub_key_b64,
            "dns_zone_verifier_key_b64": dns_zone_pub_key_b64,
            "trust_evidence_verifier_key_b64": trust_pub_key_b64,
        },
        "rustynet_artifacts": {
            "assignment_bundle": artifact_entry(ASSIGNMENT_BUNDLE),
            "traversal_bundle": artifact_entry(TRAVERSAL_BUNDLE),
            "membership_snapshot": artifact_entry(MEMBERSHIP_SNAPSHOT),
            "membership_log": artifact_entry(MEMBERSHIP_LOG),
            "dns_zone_bundle": artifact_entry(DNS_ZONE_BUNDLE),
            "trust_evidence": artifact_entry(TRUST_EVIDENCE),
        },
        "daemon_status": daemon_status,
        "known_peers": wg_peers_json,
        "remote_network_checklist": [
            "1. Add an entry for this node in your network's membership snapshot with node_id and wireguard.public_key.",
            "2. Sign a new assignment bundle that includes this node as a peer with AllowedIPs covering this node's Rustynet VPN address.",
            "3. Create a traversal bundle for your nodes targeting this node using one of the endpoint_candidates (prefer server_reflexive if available, then host, then relay).",
            "4. Distribute the signed assignment and traversal bundles to all nodes on your network that need to reach this node.",
            "5. Verify DNS zone bundle includes a record for this node's hostname if Magic DNS is in use.",
            "6. If this node is behind NAT (nat_profile.behind_nat=true), ensure a relay candidate is provisioned or port-forwarding is configured.",
            "7. Confirm latest-handshake with: sudo wg show <iface> latest-handshakes (expect a recent timestamp after peering).",
            "8. All bundles must be signed with keys trusted by both networks. Exchange verifier_keys.assignment_verifier_key_b64 with the remote CA.",
        ],
    });

    let json_output = serde_json::to_string_pretty(&discovery).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: failed to serialize discovery bundle: {err}");
        1
    })?;

    if let Some(output_path) = &config.output_path {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                eprintln!(
                    "[collect-discovery] ERROR: create output parent directory failed ({}): {err}",
                    parent.display()
                );
                1
            })?;
        }
        fs::write(output_path, &json_output).map_err(|err| {
            eprintln!(
                "[collect-discovery] ERROR: write output failed ({}): {err}",
                output_path.display()
            );
            1
        })?;
        log(
            config.quiet,
            &format!("Discovery bundle written to: {}", output_path.display()),
        );
        eprintln!();
        eprintln!("=== Cross-Network Discovery Summary ===");
        eprintln!("  Node ID      : {node_id}");
        eprintln!("  Hostname     : {host_name}");
        eprintln!(
            "  WG Public Key: {}",
            if wg_public_key.is_empty() {
                "<not found>"
            } else {
                &wg_public_key
            }
        );
        eprintln!("  WG Port      : {wg_listen_port}");
        eprintln!(
            "  Public IP    : {}",
            if public_ip.is_empty() {
                "<not detected>"
            } else {
                &public_ip
            }
        );
        eprintln!("  Behind NAT   : {behind_nat}");
        eprintln!(
            "  Daemon       : {}",
            daemon_status["active"].as_str().unwrap_or("unknown")
        );
        eprintln!("  Output file  : {}", output_path.display());
        eprintln!("=======================================");
    } else if jq_available {
        let status = Command::new("jq")
            .arg(".")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::inherit())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    stdin.write_all(json_output.as_bytes())?;
                }
                child.wait()
            })
            .map_err(|err| {
                eprintln!("[collect-discovery] ERROR: failed to run jq: {err}");
                1
            })?;
        if !status.success() {
            return Err(status.code().unwrap_or(1));
        }
    } else {
        println!("{json_output}");
    }

    log(config.quiet, "Done.");
    Ok(())
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config::default();
    let mut args = env::args_os().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "-o" | "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --output".to_string())?;
                config.output_path = Some(PathBuf::from(value));
            }
            "-i" | "--interface" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --interface".to_string())?;
                config.wg_iface = Some(os_to_string(value, "--interface")?);
            }
            "-p" | "--wg-port" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --wg-port".to_string())?;
                config.wg_port_override = Some(os_to_string(value, "--wg-port")?);
            }
            "-n" | "--node-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --node-id".to_string())?;
                config.node_id_override = Some(os_to_string(value, "--node-id")?);
            }
            "-q" | "--quiet" => config.quiet = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(format!(
                    "Unknown option: {}  (use --help for usage)",
                    arg.to_string_lossy()
                ));
            }
        }
    }

    Ok(config)
}

fn print_usage() {
    println!(
        "collect_network_discovery_info\n\n\
Usage:\n  ./collect_network_discovery_info.sh [OPTIONS]\n\n\
Options:\n  -o, --output <path>      Write JSON to <path> instead of stdout\n  -i, --interface <iface>  WireGuard interface to inspect (default: auto-detect)\n  -p, --wg-port <port>     WireGuard listen port override (default: 51820)\n  -n, --node-id <id>       Rustynet node-id (default: read from config or hostname)\n  -q, --quiet              Suppress progress messages on stderr\n  -h, --help               Show this help"
    );
}

fn log(quiet: bool, message: &str) {
    if !quiet {
        eprintln!("[collect-discovery] {message}");
    }
}

fn require_cmd(name: &str) -> Result<(), String> {
    if command_exists(name) {
        Ok(())
    } else {
        Err(format!(
            "Required command '{name}' not found. Install it and retry."
        ))
    }
}

fn command_exists(command: &str) -> bool {
    if Path::new(command).components().count() > 1 {
        return Path::new(command).is_file();
    }
    let Some(path_value) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_value).any(|dir| dir.join(command).is_file())
}

fn hostname_value() -> Result<String, String> {
    run_capture("hostname", &["-f"])
        .or_else(|_| run_capture("hostname", &[]))
        .map(|value| value.trim().to_string())
}

fn os_release_value() -> String {
    if let Ok(text) = fs::read_to_string("/etc/os-release") {
        let mut pretty = String::new();
        let mut name = String::new();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                pretty = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("NAME=") {
                name = value.trim_matches('"').to_string();
            }
        }
        if !pretty.is_empty() {
            return pretty;
        }
        if !name.is_empty() {
            return name;
        }
    }
    if let Ok(text) = fs::read_to_string("/etc/issue") {
        return text.lines().next().unwrap_or("unknown").trim().to_string();
    }
    "unknown".to_string()
}

fn resolve_node_id(config: &Config, host_name: &str) -> String {
    if let Some(node_id) = &config.node_id_override {
        return node_id.clone();
    }
    let state_node = Path::new(RUSTYNET_STATE_DIR).join("node-id");
    if let Some(value) = read_trimmed_file(&state_node) {
        if !value.is_empty() {
            return value;
        }
    }
    let config_node = Path::new(RUSTYNET_CONFIG_DIR).join("node-id");
    if let Some(value) = read_trimmed_file(&config_node) {
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(value) = resolve_node_id_from_runtime_status() {
        if !value.is_empty() {
            return value;
        }
    }
    host_name.to_string()
}

fn resolve_node_id_from_runtime_status() -> Option<String> {
    let socket = format!("{RUSTYNET_RUN_DIR}/rustynetd.sock");
    let direct = Command::new("rustynet")
        .env("RUSTYNET_DAEMON_SOCKET", socket.as_str())
        .arg("status")
        .output()
        .ok()
        .and_then(command_output_stdout_if_success);
    if let Some(status) = direct {
        if let Some(node_id) = parse_status_field(status.as_str(), "node_id") {
            return Some(node_id);
        }
    }

    Command::new("sudo")
        .args(["-n", "env"])
        .arg(format!("RUSTYNET_DAEMON_SOCKET={socket}"))
        .args(["rustynet", "status"])
        .output()
        .ok()
        .and_then(command_output_stdout_if_success)
        .and_then(|status| parse_status_field(status.as_str(), "node_id"))
}

fn command_output_stdout_if_success(output: Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn parse_status_field(status_output: &str, field_name: &str) -> Option<String> {
    let prefix = format!("{field_name}=");
    status_output
        .split_whitespace()
        .find_map(|token| token.strip_prefix(prefix.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn detect_wg_interface(wg_available: bool) -> Option<String> {
    for iface in ["rustynet0", "wg0", "wg1", "rustynet1"] {
        if run_status("ip", &["link", "show", iface]).is_ok() {
            return Some(iface.to_string());
        }
    }
    if wg_available {
        if let Ok(output) = run_capture("wg", &["show", "interfaces"]) {
            if let Some(first) = output.split_whitespace().next() {
                if !first.is_empty() {
                    return Some(first.to_string());
                }
            }
        }
    }
    None
}

fn read_wg_show(iface: &str) -> Option<String> {
    run_capture("wg", &["show", iface]).ok().or_else(|| {
        Command::new("sudo")
            .args(["-n", "wg", "show", iface])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).to_string())
                } else {
                    None
                }
            })
    })
}

fn parse_public_key_from_wg_show(text: &str) -> String {
    text.lines()
        .find_map(|line| {
            line.strip_prefix("  public key:")
                .or_else(|| line.strip_prefix("public key:"))
        })
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

fn parse_listen_port_from_wg_show(text: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix("listening port:"))
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

fn ip_interface_addresses(iface: &str) -> Result<String, i32> {
    let output = run_capture("ip", &["-4", "addr", "show", iface]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let addresses = output
        .lines()
        .filter(|line| line.trim_start().starts_with("inet "))
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(addresses)
}

fn collect_host_candidates(wg_iface: &str) -> Result<String, i32> {
    let output = run_capture("ip", &["-4", "addr", "show"]).map_err(|err| {
        eprintln!("[collect-discovery] ERROR: {err}");
        1
    })?;
    let mut result = String::new();
    let mut skip = false;
    for line in output.lines() {
        if let Some(iface) = parse_iface_header(line) {
            skip = iface == "lo" || iface == wg_iface;
            continue;
        }
        if skip {
            continue;
        }
        if let Some(ip_cidr) = line.trim().strip_prefix("inet ") {
            let mut parts = ip_cidr.split_whitespace();
            if let Some(addr) = parts.next() {
                let mut addr_parts = addr.split('/');
                let ip = addr_parts.next().unwrap_or_default();
                let prefix = addr_parts.next().unwrap_or_default();
                if !ip.starts_with("169.254.") && !ip.is_empty() {
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    result.push_str(ip);
                    result.push(':');
                    result.push_str(prefix);
                }
            }
        }
    }
    Ok(result)
}

fn parse_iface_header(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let (prefix, rest) = trimmed.split_once(": ")?;
    if !prefix.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(rest.split(':').next()?.to_string())
}

fn detect_public_ip(curl_available: bool, wget_available: bool) -> Option<String> {
    for service in [
        "https://api4.ipify.org",
        "https://icanhazip.com",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    ] {
        let candidate = if curl_available {
            run_capture("curl", &["-s", "--max-time", "5", "--retry", "1", service]).ok()
        } else if wget_available {
            run_capture("wget", &["-qO-", "--timeout=5", service]).ok()
        } else {
            None
        };
        let Some(value) = candidate else {
            continue;
        };
        let ip = value.trim();
        if is_ipv4(ip) {
            return Some(ip.to_string());
        }
    }
    None
}

fn collect_wg_peers(iface: &str, wg_available: bool) -> Result<Value, i32> {
    if iface.is_empty() || !wg_available {
        return Ok(Value::Array(Vec::new()));
    }
    let output = match run_capture("wg", &["show", iface, "dump"]) {
        Ok(text) => text,
        Err(_) => match Command::new("sudo")
            .args(["-n", "wg", "show", iface, "dump"])
            .output()
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).to_string()
            }
            _ => return Ok(Value::Array(Vec::new())),
        },
    };
    let mut peers = Vec::new();
    for (index, line) in output.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 8 {
            continue;
        }
        let endpoint = if fields[2] == "(none)" { "" } else { fields[2] };
        peers.push(json!({
            "public_key": fields[0],
            "endpoint": endpoint,
            "allowed_ips": fields[3],
            "latest_handshake_unix": parse_u64(fields[4], "known_peers.latest_handshake_unix")?,
            "rx_bytes": parse_u64(fields[5], "known_peers.rx_bytes")?,
            "tx_bytes": parse_u64(fields[6], "known_peers.tx_bytes")?,
        }));
    }
    Ok(Value::Array(peers))
}

fn artifact_entry(path: &str) -> Value {
    let exists = Path::new(path).is_file();
    let (size_bytes, mtime_unix) = if exists {
        match fs::metadata(path) {
            Ok(metadata) => {
                let size = metadata.len();
                let mtime = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0);
                (size, mtime)
            }
            Err(_) => (0, 0),
        }
    } else {
        (0, 0)
    };
    json!({
        "path": path,
        "exists": exists,
        "size_bytes": size_bytes,
        "mtime_unix": mtime_unix,
    })
}

fn build_endpoint_candidates(
    host_candidates_raw: &str,
    wg_listen_port: &str,
    public_ip: &str,
) -> Value {
    let mut candidates = Vec::new();
    for line in host_candidates_raw.lines() {
        let Some((ip, prefix)) = line.split_once(':') else {
            continue;
        };
        let priority = if ip.starts_with("10.") {
            110
        } else if ip.starts_with("192.168.") {
            120
        } else if is_172_private(ip) {
            115
        } else {
            100
        };
        candidates.push(json!({
            "type": "host",
            "endpoint": format!("{ip}:{wg_listen_port}"),
            "address": ip,
            "prefix_len": prefix,
            "priority": priority,
        }));
    }
    if !public_ip.is_empty() {
        candidates.push(json!({
            "type": "server_reflexive",
            "endpoint": format!("{public_ip}:{wg_listen_port}"),
            "address": public_ip,
            "priority": 200,
            "note": format!("public IP detected via HTTP echo; assumes port {wg_listen_port} is forwarded through NAT"),
        }));
    }
    candidates.push(json!({
        "type": "relay",
        "endpoint": "",
        "priority": 50,
        "note": "relay address is assigned by the Rustynet relay fleet; provision via signed traversal bundle",
    }));
    Value::Array(candidates)
}

fn build_peer_stanza_template(
    node_id: &str,
    host_name: &str,
    wg_public_key: &str,
    public_ip: &str,
    first_lan_ip: &str,
    wg_listen_port: &str,
) -> String {
    if wg_public_key.is_empty() {
        return String::new();
    }
    let mut stanza = String::new();
    stanza.push_str("[Peer]\n");
    stanza.push_str(&format!("# Node: {node_id}  ({host_name})\n"));
    stanza.push_str(&format!("PublicKey = {wg_public_key}\n"));
    if !public_ip.is_empty() {
        stanza.push_str(&format!("Endpoint = {public_ip}:{wg_listen_port}\n"));
    } else if !first_lan_ip.is_empty() {
        stanza.push_str(&format!(
            "Endpoint = {first_lan_ip}:{wg_listen_port}  # LAN only - no public IP detected\n"
        ));
    }
    stanza.push_str("AllowedIPs = <REPLACE_WITH_RUSTYNET_VPN_CIDR>  # e.g. 100.64.0.0/10\n");
    stanza.push_str("PersistentKeepalive = 25");
    stanza
}

fn daemon_status(run_dir: &str) -> Result<Value, i32> {
    let socket_path = Path::new(run_dir).join("rustynetd.sock");
    let socket_present = path_is_socket(&socket_path);
    if let Ok(active) = run_capture("systemctl", &["is-active", "--quiet", "rustynetd"]) {
        let _ = active;
        let pid = run_capture(
            "systemctl",
            &["show", "rustynetd", "--property=MainPID", "--value"],
        )
        .map_err(|err| {
            eprintln!("[collect-discovery] ERROR: {err}");
            1
        })?;
        return Ok(json!({
            "active": "active",
            "pid": pid.trim(),
            "socket_path": socket_path.display().to_string(),
            "socket_present": socket_present,
        }));
    }
    if socket_present {
        return Ok(json!({
            "active": "socket_present",
            "pid": "",
            "socket_path": socket_path,
            "socket_present": true,
        }));
    }
    Ok(json!({
        "active": "inactive",
        "pid": "",
        "socket_path": socket_path,
        "socket_present": false,
    }))
}

fn run_capture(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|err| format!("failed to run {command}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{command} exited with status {}",
            status_text(output.status)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_status(command: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(command)
        .args(args)
        .status()
        .map_err(|err| format!("failed to run {command}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{command} exited with status {}",
            status_text(status)
        ))
    }
}

fn read_trimmed_file(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_verifier_key_b64(path: impl AsRef<Path>) -> Option<String> {
    let value = read_trimmed_file(path)?;
    normalize_verifier_key_to_b64(value.as_str())
}

fn normalize_verifier_key_to_b64(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(bytes) = decode_hex_32(trimmed) {
        return Some(encode_base64(bytes.as_slice()));
    }
    Some(trimmed.to_string())
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let mut index = 0usize;
    while index < 32 {
        let hi = decode_hex_nibble(value.as_bytes()[index * 2])?;
        let lo = decode_hex_nibble(value.as_bytes()[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
        index += 1;
    }
    Some(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0usize;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = if index + 1 < bytes.len() {
            bytes[index + 1]
        } else {
            0
        };
        let b2 = if index + 2 < bytes.len() {
            bytes[index + 2]
        } else {
            0
        };

        let s0 = b0 >> 2;
        let s1 = ((b0 & 0x03) << 4) | (b1 >> 4);
        let s2 = ((b1 & 0x0f) << 2) | (b2 >> 6);
        let s3 = b2 & 0x3f;

        out.push(TABLE[s0 as usize] as char);
        out.push(TABLE[s1 as usize] as char);
        if index + 1 < bytes.len() {
            out.push(TABLE[s2 as usize] as char);
        } else {
            out.push('=');
        }
        if index + 2 < bytes.len() {
            out.push(TABLE[s3 as usize] as char);
        } else {
            out.push('=');
        }
        index += 3;
    }
    out
}

fn path_is_socket(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                metadata.file_type().is_socket()
            }
            #[cfg(not(unix))]
            {
                metadata.file_type().is_file()
            }
        }
        Err(_) => false,
    }
}

fn os_to_string(value: OsString, flag: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("{flag} must be valid UTF-8"))
}

fn parse_u64(text: &str, field: &str) -> Result<u64, i32> {
    text.trim().parse::<u64>().map_err(|_| {
        eprintln!("[collect-discovery] ERROR: {field} must be an integer");
        1
    })
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.into_iter().all(|part| part.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_hex_32, encode_base64, normalize_verifier_key_to_b64, parse_status_field,
    };

    #[test]
    fn normalize_verifier_key_converts_hex_to_base64() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let converted = normalize_verifier_key_to_b64(hex).expect("hex verifier key should parse");
        assert_eq!(converted, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    }

    #[test]
    fn normalize_verifier_key_preserves_base64() {
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let converted = normalize_verifier_key_to_b64(b64).expect("base64 verifier key should parse");
        assert_eq!(converted, b64);
    }

    #[test]
    fn encode_base64_matches_expected_output() {
        let decoded = decode_hex_32(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("hex should decode");
        assert_eq!(encode_base64(decoded.as_slice()), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    }

    #[test]
    fn parse_status_field_reads_node_id() {
        let status = "node_id=client-1 node_role=client state=ExitActive";
        let node_id = parse_status_field(status, "node_id").expect("node_id should parse");
        assert_eq!(node_id, "client-1");
    }
}

fn is_172_private(ip: &str) -> bool {
    let mut parts = ip.split('.');
    matches!(
        (
            parts.next().and_then(|v| v.parse::<u8>().ok()),
            parts.next().and_then(|v| v.parse::<u8>().ok()),
        ),
        (Some(172), Some(second)) if (16..=31).contains(&second)
    )
}

fn status_text(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string())
}
