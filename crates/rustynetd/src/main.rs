#![forbid(unsafe_code)]

use rustynet_crypto::{KeyCustodyPermissionPolicy, write_encrypted_key_file};
use rustynetd::daemon::{
    DEFAULT_AUTO_PORT_FORWARD_EXIT, DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS, DEFAULT_EGRESS_INTERFACE,
    DEFAULT_FAIL_CLOSED_SSH_ALLOW, DEFAULT_MAX_RECONCILE_FAILURES, DEFAULT_MEMBERSHIP_LOG_PATH,
    DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH,
    DEFAULT_MEMBERSHIP_WATERMARK_PATH, DEFAULT_NODE_ID, DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS,
    DEFAULT_RECONCILE_INTERVAL_MS, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, DEFAULT_SOCKET_PATH,
    DEFAULT_STATE_PATH, DEFAULT_TRAVERSAL_BUNDLE_PATH, DEFAULT_TRAVERSAL_MAX_AGE_SECS,
    DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS, DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES,
    DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS, DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES,
    DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS, DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS,
    DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS, DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH,
    DEFAULT_TRAVERSAL_WATERMARK_PATH, DEFAULT_TRUST_EVIDENCE_PATH, DEFAULT_TRUST_VERIFIER_KEY_PATH,
    DEFAULT_TRUST_WATERMARK_PATH, DEFAULT_TRUSTED_HELPER_SOCKET_PATH,
    DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WG_INTERFACE, DEFAULT_WG_KEY_PASSPHRASE_PATH,
    DEFAULT_WG_LISTEN_PORT, DEFAULT_WG_PUBLIC_KEY_PATH, DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH,
    DaemonBackendMode, DaemonConfig, DaemonDataplaneMode, NodeRole, run_daemon,
};
use rustynetd::key_material::{
    initialize_encrypted_key_material, migrate_existing_private_key_material,
    read_passphrase_file_explicit, remove_file_if_present, store_passphrase_in_os_secure_store,
};
use rustynetd::perf;
use rustynetd::phase10::ManagementCidr;
use rustynetd::privileged_helper::{PrivilegedHelperConfig, run_privileged_helper};
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize};

const MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV: &str =
    "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_PATH";

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynetd startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return Err(help_text());
    }

    match args.as_slice() {
        [flag, output_path] if flag == "--emit-phase1-baseline" => {
            perf::write_phase1_baseline_report(output_path)?;
            println!("phase1 baseline report emitted: {output_path}");
            Ok(())
        }
        [cmd, rest @ ..] if cmd == "daemon" => {
            let config = parse_daemon_config(rest)?;
            run_daemon(config).map_err(|err| err.to_string())
        }
        [cmd, rest @ ..] if cmd == "privileged-helper" => run_privileged_helper_command(rest),
        [cmd, rest @ ..] if cmd == "key" => run_key_command(rest),
        [cmd, rest @ ..] if cmd == "membership" => run_membership_command(rest),
        _ => Err(help_text()),
    }
}

fn run_key_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "key subcommand is required (supported: init, migrate, store-passphrase)".to_string(),
        );
    }
    match args[0].as_str() {
        "init" => run_key_init(&args[1..]),
        "migrate" => run_key_migrate(&args[1..]),
        "store-passphrase" => run_key_store_passphrase(&args[1..]),
        other => Err(format!("unknown key subcommand: {other}")),
    }
}

fn run_privileged_helper_command(args: &[String]) -> Result<(), String> {
    let mut config = PrivilegedHelperConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket requires a value".to_string())?;
                config.socket_path = value.into();
                index += 2;
            }
            Some("--allowed-uid") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--allowed-uid requires a value".to_string())?;
                config.allowed_uid = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid --allowed-uid value: {err}"))?;
                index += 2;
            }
            Some("--allowed-gid") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--allowed-gid requires a value".to_string())?;
                let gid = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid --allowed-gid value: {err}"))?;
                config.allowed_gid = Some(gid);
                index += 2;
            }
            Some("--timeout-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--timeout-ms requires a value".to_string())?;
                let timeout_ms = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --timeout-ms value: {err}"))?;
                if timeout_ms == 0 {
                    return Err("--timeout-ms must be greater than zero".to_string());
                }
                config.io_timeout = std::time::Duration::from_millis(timeout_ms);
                index += 2;
            }
            Some(flag) => return Err(format!("unknown privileged-helper argument: {flag}")),
            None => break,
        }
    }
    run_privileged_helper(config)
}

fn run_key_init(args: &[String]) -> Result<(), String> {
    let mut runtime_path = DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH.to_string();
    let mut encrypted_path = DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_string();
    let mut public_path = DEFAULT_WG_PUBLIC_KEY_PATH.to_string();
    let mut passphrase_path = DEFAULT_WG_KEY_PASSPHRASE_PATH.to_string();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--runtime-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--runtime-private-key requires a value".to_string())?;
                runtime_path = value.clone();
                index += 2;
            }
            Some("--encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--encrypted-private-key requires a value".to_string())?;
                encrypted_path = value.clone();
                index += 2;
            }
            Some("--public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--public-key requires a value".to_string())?;
                public_path = value.clone();
                index += 2;
            }
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_string())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown key init argument: {flag}")),
            None => break,
        }
    }

    for path in [
        &runtime_path,
        &encrypted_path,
        &public_path,
        &passphrase_path,
    ] {
        if !path.starts_with('/') {
            return Err(format!("path must be absolute: {path}"));
        }
    }

    initialize_encrypted_key_material(
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        Some(std::path::Path::new(&passphrase_path)),
        force,
    )?;

    println!(
        "key init complete: runtime_private_key={runtime_path} encrypted_private_key={encrypted_path} public_key={public_path}",
    );
    Ok(())
}

fn run_key_migrate(args: &[String]) -> Result<(), String> {
    let mut existing_private_key_path = String::new();
    let mut runtime_path = DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH.to_string();
    let mut encrypted_path = DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_string();
    let mut public_path = DEFAULT_WG_PUBLIC_KEY_PATH.to_string();
    let mut passphrase_path = DEFAULT_WG_KEY_PASSPHRASE_PATH.to_string();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--existing-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--existing-private-key requires a value".to_string())?;
                existing_private_key_path = value.clone();
                index += 2;
            }
            Some("--runtime-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--runtime-private-key requires a value".to_string())?;
                runtime_path = value.clone();
                index += 2;
            }
            Some("--encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--encrypted-private-key requires a value".to_string())?;
                encrypted_path = value.clone();
                index += 2;
            }
            Some("--public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--public-key requires a value".to_string())?;
                public_path = value.clone();
                index += 2;
            }
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_string())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown key migrate argument: {flag}")),
            None => break,
        }
    }

    if existing_private_key_path.is_empty() {
        return Err("--existing-private-key is required".to_string());
    }

    for path in [
        &existing_private_key_path,
        &runtime_path,
        &encrypted_path,
        &public_path,
        &passphrase_path,
    ] {
        if !path.starts_with('/') {
            return Err(format!("path must be absolute: {path}"));
        }
    }

    migrate_existing_private_key_material(
        std::path::Path::new(&existing_private_key_path),
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        Some(std::path::Path::new(&passphrase_path)),
        force,
    )?;

    println!(
        "key migrate complete: existing_private_key={existing_private_key_path} runtime_private_key={runtime_path} encrypted_private_key={encrypted_path} public_key={public_path}",
    );
    Ok(())
}

fn run_key_store_passphrase(args: &[String]) -> Result<(), String> {
    let mut passphrase_path = String::new();
    let mut keychain_account: Option<String> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_string())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--keychain-account") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--keychain-account requires a value".to_string())?;
                keychain_account = Some(value.clone());
                index += 2;
            }
            Some(flag) => return Err(format!("unknown key store-passphrase argument: {flag}")),
            None => break,
        }
    }

    if passphrase_path.is_empty() {
        return Err("--passphrase-file is required".to_string());
    }
    if !passphrase_path.starts_with('/') {
        return Err(format!("path must be absolute: {passphrase_path}"));
    }

    store_passphrase_in_os_secure_store(
        std::path::Path::new(&passphrase_path),
        keychain_account.as_deref(),
    )?;

    println!(
        "key passphrase store complete: passphrase_file={} keychain_account={}",
        passphrase_path,
        keychain_account.as_deref().unwrap_or("<env>")
    );
    Ok(())
}

fn parse_daemon_config(args: &[String]) -> Result<DaemonConfig, String> {
    let mut config = DaemonConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--node-id") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--node-id requires a value".to_string())?;
                config.node_id = value.clone();
                index += 2;
            }
            Some("--node-role") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--node-role requires a value".to_string())?;
                config.node_role = value.parse::<NodeRole>()?;
                index += 2;
            }
            Some("--socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket requires a value".to_string())?;
                config.socket_path = value.into();
                index += 2;
            }
            Some("--state") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state requires a value".to_string())?;
                config.state_path = value.into();
                index += 2;
            }
            Some("--trust-evidence") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-evidence requires a value".to_string())?;
                config.trust_evidence_path = value.into();
                index += 2;
            }
            Some("--trust-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-verifier-key requires a value".to_string())?;
                config.trust_verifier_key_path = value.into();
                index += 2;
            }
            Some("--trust-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-watermark requires a value".to_string())?;
                config.trust_watermark_path = value.into();
                index += 2;
            }
            Some("--membership-snapshot") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-snapshot requires a value".to_string())?;
                config.membership_snapshot_path = value.into();
                index += 2;
            }
            Some("--membership-log") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-log requires a value".to_string())?;
                config.membership_log_path = value.into();
                index += 2;
            }
            Some("--membership-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-watermark requires a value".to_string())?;
                config.membership_watermark_path = value.into();
                index += 2;
            }
            Some("--auto-tunnel-enforce") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-enforce requires a value".to_string())?;
                config.auto_tunnel_enforce = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid auto-tunnel-enforce value: expected true/false".to_string()
                        );
                    }
                };
                index += 2;
            }
            Some("--auto-tunnel-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-bundle requires a value".to_string())?;
                config.auto_tunnel_bundle_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-verifier-key requires a value".to_string())?;
                config.auto_tunnel_verifier_key_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-watermark requires a value".to_string())?;
                config.auto_tunnel_watermark_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-max-age-secs requires a value".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid auto tunnel max age: {err}"))?;
                config.auto_tunnel_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "auto tunnel max age must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--dns-zone-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-bundle requires a value".to_string())?;
                config.dns_zone_bundle_path = value.into();
                index += 2;
            }
            Some("--dns-zone-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-verifier-key requires a value".to_string())?;
                config.dns_zone_verifier_key_path = value.into();
                index += 2;
            }
            Some("--dns-zone-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-watermark requires a value".to_string())?;
                config.dns_zone_watermark_path = value.into();
                index += 2;
            }
            Some("--dns-zone-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-max-age-secs requires a value".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid dns zone max age: {err}"))?;
                config.dns_zone_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "dns zone max age must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--dns-zone-name") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-name requires a value".to_string())?;
                config.dns_zone_name = value.clone();
                index += 2;
            }
            Some("--dns-resolver-bind-addr") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-resolver-bind-addr requires a value".to_string())?;
                config.dns_resolver_bind_addr = value
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid dns resolver bind addr: {err}"))?;
                index += 2;
            }
            Some("--traversal-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-bundle requires a value".to_string())?;
                config.traversal_bundle_path = value.into();
                index += 2;
            }
            Some("--traversal-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-verifier-key requires a value".to_string())?;
                config.traversal_verifier_key_path = value.into();
                index += 2;
            }
            Some("--traversal-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-watermark requires a value".to_string())?;
                config.traversal_watermark_path = value.into();
                index += 2;
            }
            Some("--traversal-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-max-age-secs requires a value".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal max age: {err}"))?;
                config.traversal_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "traversal max age must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--traversal-probe-max-candidates") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-max-candidates requires a value".to_string()
                })?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid traversal probe max candidates: {err}"))?;
                config.traversal_probe_max_candidates =
                    NonZeroUsize::new(parsed).ok_or_else(|| {
                        "traversal probe max candidates must be greater than 0".to_string()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-max-pairs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-probe-max-pairs requires a value".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid traversal probe max pairs: {err}"))?;
                config.traversal_probe_max_pairs = NonZeroUsize::new(parsed).ok_or_else(|| {
                    "traversal probe max pairs must be greater than 0".to_string()
                })?;
                index += 2;
            }
            Some("--traversal-probe-rounds") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-probe-rounds requires a value".to_string())?;
                let parsed = value
                    .parse::<u8>()
                    .map_err(|err| format!("invalid traversal probe rounds: {err}"))?;
                config.traversal_probe_simultaneous_open_rounds = NonZeroU8::new(parsed)
                    .ok_or_else(|| "traversal probe rounds must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--traversal-probe-round-spacing-ms") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-round-spacing-ms requires a value".to_string()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe round spacing: {err}"))?;
                config.traversal_probe_round_spacing_ms =
                    NonZeroU64::new(parsed).ok_or_else(|| {
                        "traversal probe round spacing must be greater than 0".to_string()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-relay-switch-after-failures") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-relay-switch-after-failures requires a value".to_string()
                })?;
                let parsed = value.parse::<u8>().map_err(|err| {
                    format!("invalid traversal probe relay switch threshold: {err}")
                })?;
                config.traversal_probe_relay_switch_after_failures = NonZeroU8::new(parsed)
                    .ok_or_else(|| {
                        "traversal probe relay switch threshold must be greater than 0".to_string()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-handshake-freshness-secs") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-handshake-freshness-secs requires a value".to_string()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe handshake freshness: {err}"))?;
                config.traversal_probe_handshake_freshness_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| {
                        "traversal probe handshake freshness must be greater than 0".to_string()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-reprobe-interval-secs") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-reprobe-interval-secs requires a value".to_string()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe reprobe interval: {err}"))?;
                config.traversal_probe_reprobe_interval_secs =
                    NonZeroU64::new(parsed).ok_or_else(|| {
                        "traversal probe reprobe interval must be greater than 0".to_string()
                    })?;
                index += 2;
            }
            Some("--backend") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--backend requires a value".to_string())?;
                config.backend_mode = match value.as_str() {
                    "linux-wireguard" => DaemonBackendMode::LinuxWireguard,
                    "macos-wireguard" => DaemonBackendMode::MacosWireguard,
                    _ => {
                        return Err(
                            "invalid backend value: expected linux-wireguard or macos-wireguard"
                                .to_string(),
                        );
                    }
                };
                index += 2;
            }
            Some("--wg-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-interface requires a value".to_string())?;
                config.wg_interface = value.clone();
                index += 2;
            }
            Some("--wg-listen-port") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-listen-port requires a value".to_string())?;
                let port = value
                    .parse::<u16>()
                    .map_err(|err| format!("invalid --wg-listen-port value: {err}"))?;
                if port == 0 {
                    return Err("--wg-listen-port must be in range 1-65535".to_string());
                }
                config.wg_listen_port = port;
                index += 2;
            }
            Some("--wg-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-private-key requires a value".to_string())?;
                config.wg_private_key_path = Some(value.into());
                index += 2;
            }
            Some("--wg-encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-encrypted-private-key requires a value".to_string())?;
                config.wg_encrypted_private_key_path = Some(value.into());
                index += 2;
            }
            Some("--wg-key-passphrase") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-key-passphrase requires a value".to_string())?;
                config.wg_key_passphrase_path = Some(value.into());
                index += 2;
            }
            Some("--wg-public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-public-key requires a value".to_string())?;
                config.wg_public_key_path = Some(value.into());
                index += 2;
            }
            Some("--egress-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--egress-interface requires a value".to_string())?;
                config.egress_interface = value.clone();
                index += 2;
            }
            Some("--remote-ops-token-verifier-key") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--remote-ops-token-verifier-key requires a value".to_string()
                })?;
                config.remote_ops_token_verifier_key_path = Some(value.into());
                index += 2;
            }
            Some("--remote-ops-expected-subject") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--remote-ops-expected-subject requires a value".to_string())?;
                config.remote_ops_expected_subject = value.clone();
                index += 2;
            }
            Some("--auto-port-forward-exit") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-port-forward-exit requires a value".to_string())?;
                config.auto_port_forward_exit = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid auto-port-forward-exit value: expected true/false".to_string()
                        );
                    }
                };
                index += 2;
            }
            Some("--auto-port-forward-lease-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-port-forward-lease-secs requires a value".to_string())?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid auto port-forward lease: {err}"))?;
                config.auto_port_forward_lease_secs = NonZeroU32::new(parsed).ok_or_else(|| {
                    "auto-port-forward-lease-secs must be greater than 0".to_string()
                })?;
                index += 2;
            }
            Some("--dataplane-mode") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dataplane-mode requires a value".to_string())?;
                config.dataplane_mode = match value.as_str() {
                    "shell" => DaemonDataplaneMode::Shell,
                    "hybrid-native" => DaemonDataplaneMode::HybridNative,
                    _ => {
                        return Err(
                            "invalid dataplane mode: expected shell or hybrid-native".to_string()
                        );
                    }
                };
                index += 2;
            }
            Some("--privileged-helper-socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--privileged-helper-socket requires a value".to_string())?;
                config.privileged_helper_socket_path = Some(value.into());
                index += 2;
            }
            Some("--privileged-helper-timeout-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--privileged-helper-timeout-ms requires a value".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid privileged helper timeout: {err}"))?;
                config.privileged_helper_timeout_ms = NonZeroU64::new(parsed).ok_or_else(|| {
                    "privileged helper timeout must be greater than 0".to_string()
                })?;
                index += 2;
            }
            Some("--max-requests") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-requests requires a value".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid max requests: {err}"))?;
                config.max_requests = Some(
                    NonZeroUsize::new(parsed)
                        .ok_or_else(|| "max requests must be greater than 0".to_string())?,
                );
                index += 2;
            }
            Some("--reconcile-interval-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--reconcile-interval-ms requires a value".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid reconcile interval: {err}"))?;
                config.reconcile_interval_ms = NonZeroU64::new(parsed)
                    .ok_or_else(|| "reconcile interval must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--max-reconcile-failures") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-reconcile-failures requires a value".to_string())?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid max reconcile failures: {err}"))?;
                config.max_reconcile_failures = NonZeroU32::new(parsed)
                    .ok_or_else(|| "max reconcile failures must be greater than 0".to_string())?;
                index += 2;
            }
            Some("--fail-closed-ssh-allow") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--fail-closed-ssh-allow requires a value".to_string())?;
                config.fail_closed_ssh_allow = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid fail-closed-ssh-allow value: expected true/false".to_string()
                        );
                    }
                };
                index += 2;
            }
            Some("--fail-closed-ssh-allow-cidrs") => {
                if let Some(value) = args.get(index + 1) {
                    if value.starts_with("--") {
                        config.fail_closed_ssh_allow_cidrs.clear();
                        index += 1;
                    } else {
                        config.fail_closed_ssh_allow_cidrs = value
                            .split(',')
                            .map(str::trim)
                            .filter(|entry| !entry.is_empty())
                            .map(str::parse::<ManagementCidr>)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|err| {
                                format!("invalid --fail-closed-ssh-allow-cidrs value: {err}")
                            })?;
                        index += 2;
                    }
                } else {
                    config.fail_closed_ssh_allow_cidrs.clear();
                    index += 1;
                }
            }
            Some(flag) => {
                return Err(format!("unknown daemon argument: {flag}"));
            }
            None => break,
        }
    }
    Ok(config)
}

fn run_membership_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("init") => run_membership_init(&args[1..]),
        Some(other) => Err(format!("unknown membership subcommand: {other}")),
        None => Err("membership subcommand required (supported: init)".to_string()),
    }
}

fn run_membership_init(args: &[String]) -> Result<(), String> {
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
        persist_membership_snapshot,
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroize;

    let mut snapshot_path = DEFAULT_MEMBERSHIP_SNAPSHOT_PATH.to_string();
    let mut log_path = DEFAULT_MEMBERSHIP_LOG_PATH.to_string();
    let mut watermark_path = DEFAULT_MEMBERSHIP_WATERMARK_PATH.to_string();
    let mut owner_signing_key_path = DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH.to_string();
    let mut owner_signing_key_passphrase_path =
        std::env::var(MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV).ok();
    let mut node_id = read_hostname_short();
    let mut network_id = "local-net".to_string();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--snapshot") => {
                snapshot_path = args
                    .get(index + 1)
                    .ok_or("--snapshot requires a value")?
                    .clone();
                index += 2;
            }
            Some("--log") => {
                log_path = args.get(index + 1).ok_or("--log requires a value")?.clone();
                index += 2;
            }
            Some("--watermark") => {
                watermark_path = args
                    .get(index + 1)
                    .ok_or("--watermark requires a value")?
                    .clone();
                index += 2;
            }
            Some("--owner-signing-key") => {
                owner_signing_key_path = args
                    .get(index + 1)
                    .ok_or("--owner-signing-key requires a value")?
                    .clone();
                index += 2;
            }
            Some("--owner-signing-key-passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or("--owner-signing-key-passphrase-file requires a value")?
                    .clone();
                owner_signing_key_passphrase_path = Some(value);
                index += 2;
            }
            Some("--node-id") => {
                node_id = args
                    .get(index + 1)
                    .ok_or("--node-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--network-id") => {
                network_id = args
                    .get(index + 1)
                    .ok_or("--network-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown membership init argument: {flag}")),
            None => break,
        }
    }

    if !snapshot_path.starts_with('/') {
        return Err(format!("snapshot path must be absolute: {snapshot_path}"));
    }
    if !log_path.starts_with('/') {
        return Err(format!("log path must be absolute: {log_path}"));
    }
    if !watermark_path.starts_with('/') {
        return Err(format!("watermark path must be absolute: {watermark_path}"));
    }
    if !owner_signing_key_path.starts_with('/') {
        return Err(format!(
            "owner signing key path must be absolute: {owner_signing_key_path}"
        ));
    }
    let owner_signing_key_passphrase_path =
        owner_signing_key_passphrase_path.ok_or_else(|| {
            format!(
                "owner signing key passphrase path is required; pass --owner-signing-key-passphrase-file or set {MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV}",
            )
        })?;
    if !owner_signing_key_passphrase_path.starts_with('/') {
        return Err(format!(
            "owner signing key passphrase path must be absolute: {owner_signing_key_passphrase_path}"
        ));
    }

    if !force
        && (std::path::Path::new(&snapshot_path).exists()
            || std::path::Path::new(&log_path).exists()
            || std::path::Path::new(&watermark_path).exists()
            || std::path::Path::new(&owner_signing_key_path).exists())
    {
        return Err(format!(
            "membership files already exist at {snapshot_path}, {log_path}, {watermark_path}, or {owner_signing_key_path}; use --force to overwrite"
        ));
    }

    for path_str in [
        &snapshot_path,
        &log_path,
        &watermark_path,
        &owner_signing_key_path,
    ] {
        if let Some(parent) = std::path::Path::new(path_str.as_str()).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
        }
    }

    if std::path::Path::new(&watermark_path).exists() {
        std::fs::remove_file(&watermark_path)
            .map_err(|e| format!("failed to remove membership watermark {watermark_path}: {e}"))?;
    }

    let mut node_key_bytes = [0u8; 32];
    let mut approver_key_bytes = [0u8; 32];
    fill_random_bytes(&mut node_key_bytes)
        .map_err(|e| format!("failed to generate node identity key: {e}"))?;
    fill_random_bytes(&mut approver_key_bytes)
        .map_err(|e| format!("failed to generate approver key: {e}"))?;

    let init_result = (|| -> Result<String, String> {
        let approver_signing = SigningKey::from_bytes(&approver_key_bytes);
        let approver_pubkey_hex = encode_hex(approver_signing.verifying_key().as_bytes());
        let node_pubkey_hex = encode_hex(&node_key_bytes);
        let owner_approver_id = format!("{node_id}-owner");

        persist_owner_signing_key_encrypted(
            std::path::Path::new(&owner_signing_key_path),
            &approver_key_bytes,
            std::path::Path::new(&owner_signing_key_passphrase_path),
            force,
        )?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: network_id.clone(),
            epoch: 1,
            nodes: vec![MembershipNode {
                node_id: node_id.clone(),
                node_pubkey_hex,
                owner: node_id.clone(),
                status: MembershipNodeStatus::Active,
                roles: vec![],
                joined_at_unix: now,
                updated_at_unix: now,
            }],
            approver_set: vec![MembershipApprover {
                approver_id: owner_approver_id.clone(),
                approver_pubkey_hex,
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: now,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };

        persist_membership_snapshot(&snapshot_path, &state)
            .map_err(|e| format!("failed to write membership snapshot: {e}"))?;

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut log_file = opts
            .open(&log_path)
            .map_err(|e| format!("failed to create membership log: {e}"))?;
        log_file
            .write_all(format!("version={MEMBERSHIP_SCHEMA_VERSION}\n").as_bytes())
            .map_err(|e| format!("failed to write membership log: {e}"))?;
        Ok(owner_approver_id)
    })();

    node_key_bytes.zeroize();
    approver_key_bytes.zeroize();
    let owner_approver_id = init_result?;

    println!(
        "membership init complete: snapshot={snapshot_path} log={log_path} watermark_reset={watermark_path} owner_signing_key={owner_signing_key_path}"
    );
    println!("  node_id={node_id} network_id={network_id} owner_approver_id={owner_approver_id}");
    Ok(())
}

fn fill_random_bytes(buf: &mut [u8]) -> Result<(), std::io::Error> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn encrypted_secret_permission_policy(path: &std::path::Path) -> KeyCustodyPermissionPolicy {
    let mut policy = KeyCustodyPermissionPolicy::default();
    if matches!(path.parent(), Some(parent) if parent == std::path::Path::new("/etc/rustynet")) {
        // Encrypted signing artifacts currently coexist with daemon-readable verifier
        // material under /etc/rustynet on Linux.
        policy.required_directory_mode = 0o750;
    }
    policy
}

fn persist_owner_signing_key_encrypted(
    path: &std::path::Path,
    key_bytes: &[u8; 32],
    passphrase_path: &std::path::Path,
    force: bool,
) -> Result<(), String> {
    use std::io::ErrorKind;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "owner signing key path must not be a symlink: {}",
                    path.display()
                ));
            }
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "owner signing key path must reference a regular file: {}",
                    path.display()
                ));
            }
            if !force {
                return Err(format!(
                    "owner signing key already exists at {}; use --force to overwrite",
                    path.display()
                ));
            }
            remove_file_if_present(path)?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect owner signing key {}: {err}",
                path.display()
            ));
        }
    }

    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "owner signing key passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("owner signing key path has no parent: {}", path.display()))?;
    let permission_policy = encrypted_secret_permission_policy(path);
    write_encrypted_key_file(
        parent,
        path,
        key_bytes,
        passphrase.as_str(),
        permission_policy,
    )
    .map_err(|err| {
        format!(
            "failed to persist encrypted owner signing key {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn read_hostname_short() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .and_then(|s| s.trim().split('.').next().map(str::to_string))
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "local".to_string())
}

fn help_text() -> String {
    [
        "rustynetd usage:",
        "  rustynetd daemon [--node-id <id>] [--node-role <admin|client|blind_exit>] [--socket <path>] [--state <path>] [--trust-evidence <path>] [--trust-verifier-key <path>] [--trust-watermark <path>] [--membership-snapshot <path>] [--membership-log <path>] [--membership-watermark <path>] [--auto-tunnel-enforce <true|false>] [--auto-tunnel-bundle <path>] [--auto-tunnel-verifier-key <path>] [--auto-tunnel-watermark <path>] [--auto-tunnel-max-age-secs <secs>] [--dns-zone-bundle <path>] [--dns-zone-verifier-key <path>] [--dns-zone-watermark <path>] [--dns-zone-max-age-secs <secs>] [--dns-zone-name <name>] [--dns-resolver-bind-addr <addr:port>] [--traversal-bundle <path>] [--traversal-verifier-key <path>] [--traversal-watermark <path>] [--traversal-max-age-secs <secs>] [--traversal-probe-max-candidates <n>] [--traversal-probe-max-pairs <n>] [--traversal-probe-rounds <n>] [--traversal-probe-round-spacing-ms <ms>] [--traversal-probe-relay-switch-after-failures <n>] [--traversal-probe-handshake-freshness-secs <secs>] [--traversal-probe-reprobe-interval-secs <secs>] [--backend <linux-wireguard|macos-wireguard>] [--wg-interface <name>] [--wg-listen-port <1-65535>] [--wg-private-key <path>] [--wg-encrypted-private-key <path>] [--wg-key-passphrase <path>] [--wg-public-key <path>] [--egress-interface <name|auto>] [--remote-ops-token-verifier-key <path>] [--remote-ops-expected-subject <subject>] [--auto-port-forward-exit <true|false>] [--auto-port-forward-lease-secs <secs>] [--dataplane-mode <shell|hybrid-native>] [--privileged-helper-socket <path>] [--privileged-helper-timeout-ms <ms>] [--reconcile-interval-ms <ms>] [--max-reconcile-failures <n>] [--fail-closed-ssh-allow <true|false>] [--fail-closed-ssh-allow-cidrs <cidr[,cidr...]>] [--max-requests <n>]",
        "  rustynetd privileged-helper [--socket <path>] [--allowed-uid <uid>] [--allowed-gid <gid>] [--timeout-ms <ms>]",
        "  rustynetd key init [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key migrate --existing-private-key <path> [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key store-passphrase --passphrase-file <path> [--keychain-account <name>]",
        "  rustynetd membership init [--snapshot <path>] [--log <path>] [--watermark <path>] [--owner-signing-key <path>] [--owner-signing-key-passphrase-file <path>] [--node-id <id>] [--network-id <id>] [--force]",
        "  rustynetd --emit-phase1-baseline <path>",
        "",
        "defaults:",
        &format!("  node_id={DEFAULT_NODE_ID}"),
        &format!("  node_role={:?}", NodeRole::default()),
        &format!("  socket={DEFAULT_SOCKET_PATH}"),
        &format!("  state={DEFAULT_STATE_PATH}"),
        &format!("  trust_evidence={DEFAULT_TRUST_EVIDENCE_PATH}"),
        &format!("  trust_verifier_key={DEFAULT_TRUST_VERIFIER_KEY_PATH}"),
        &format!("  trust_watermark={DEFAULT_TRUST_WATERMARK_PATH}"),
        &format!("  membership_snapshot={DEFAULT_MEMBERSHIP_SNAPSHOT_PATH}"),
        &format!("  membership_log={DEFAULT_MEMBERSHIP_LOG_PATH}"),
        &format!("  membership_watermark={DEFAULT_MEMBERSHIP_WATERMARK_PATH}"),
        &format!("  traversal_bundle={DEFAULT_TRAVERSAL_BUNDLE_PATH}"),
        &format!("  traversal_verifier_key={DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH}"),
        &format!("  traversal_watermark={DEFAULT_TRAVERSAL_WATERMARK_PATH}"),
        &format!("  traversal_max_age_secs={DEFAULT_TRAVERSAL_MAX_AGE_SECS}"),
        &format!(
            "  traversal_probe_max_candidates={DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES}"
        ),
        &format!("  traversal_probe_max_pairs={DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS}"),
        &format!(
            "  traversal_probe_rounds={DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS}"
        ),
        &format!(
            "  traversal_probe_round_spacing_ms={DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS}"
        ),
        &format!(
            "  traversal_probe_relay_switch_after_failures={DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES}"
        ),
        &format!(
            "  traversal_probe_handshake_freshness_secs={DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS}"
        ),
        &format!(
            "  traversal_probe_reprobe_interval_secs={DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS}"
        ),
        &format!(
            "  membership_owner_signing_key={DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH}"
        ),
        &format!("  backend={:?}", DaemonBackendMode::default()),
        &format!("  wg_interface={DEFAULT_WG_INTERFACE}"),
        &format!("  wg_listen_port={DEFAULT_WG_LISTEN_PORT}"),
        &format!("  wg_private_key={DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH}"),
        &format!("  wg_encrypted_private_key={DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH}"),
        &format!("  wg_key_passphrase={DEFAULT_WG_KEY_PASSPHRASE_PATH}"),
        &format!("  wg_public_key={DEFAULT_WG_PUBLIC_KEY_PATH}"),
        &format!("  egress_interface={DEFAULT_EGRESS_INTERFACE}"),
        "  remote_ops_token_verifier_key=<disabled>",
        &format!("  remote_ops_expected_subject={DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT}"),
        &format!("  auto_port_forward_exit={DEFAULT_AUTO_PORT_FORWARD_EXIT}"),
        &format!(
            "  auto_port_forward_lease_secs={DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS}"
        ),
        &format!(
            "  dataplane_mode={:?}",
            DaemonDataplaneMode::default()
        ),
        &format!("  privileged_helper_socket={DEFAULT_TRUSTED_HELPER_SOCKET_PATH}"),
        &format!(
            "  privileged_helper_timeout_ms={DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS}"
        ),
        &format!("  reconcile_interval_ms={DEFAULT_RECONCILE_INTERVAL_MS}"),
        &format!("  max_reconcile_failures={DEFAULT_MAX_RECONCILE_FAILURES}"),
        &format!("  fail_closed_ssh_allow={DEFAULT_FAIL_CLOSED_SSH_ALLOW}"),
        "  fail_closed_ssh_allow_cidrs=<empty>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::parse_daemon_config;
    use rustynetd::daemon::{
        DEFAULT_DNS_RESOLVER_BIND_ADDR, DEFAULT_DNS_ZONE_BUNDLE_PATH,
        DEFAULT_DNS_ZONE_MAX_AGE_SECS, DEFAULT_DNS_ZONE_NAME, DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH,
        DEFAULT_DNS_ZONE_WATERMARK_PATH, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT,
    };
    use rustynetd::phase10::ManagementCidr;

    #[test]
    fn parse_daemon_config_allows_empty_fail_closed_cidrs_when_value_is_omitted() {
        let args = vec!["--fail-closed-ssh-allow-cidrs".to_string()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.fail_closed_ssh_allow_cidrs.is_empty());
    }

    #[test]
    fn parse_daemon_config_allows_empty_fail_closed_cidrs_when_next_flag_follows() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_string(),
            "--node-id".to_string(),
            "node-a".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.fail_closed_ssh_allow_cidrs.is_empty());
        assert_eq!(config.node_id.as_str(), "node-a");
    }

    #[test]
    fn parse_daemon_config_parses_explicit_fail_closed_cidrs() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_string(),
            "192.168.0.0/24,fd00::/64".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.fail_closed_ssh_allow_cidrs,
            vec![
                "192.168.0.0/24"
                    .parse::<ManagementCidr>()
                    .expect("cidr should parse"),
                "fd00::/64"
                    .parse::<ManagementCidr>()
                    .expect("cidr should parse"),
            ]
        );
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_fail_closed_cidrs() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_string(),
            "not-a-cidr".to_string(),
        ];
        let err = parse_daemon_config(&args).expect_err("invalid cidr should fail parsing");
        assert!(err.contains("invalid --fail-closed-ssh-allow-cidrs value"));
    }

    #[test]
    fn parse_daemon_config_parses_auto_port_forward_settings() {
        let args = vec![
            "--auto-port-forward-exit".to_string(),
            "true".to_string(),
            "--auto-port-forward-lease-secs".to_string(),
            "1200".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.auto_port_forward_exit);
        assert_eq!(config.auto_port_forward_lease_secs.get(), 1200);
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_auto_port_forward_exit_value() {
        let args = vec!["--auto-port-forward-exit".to_string(), "maybe".to_string()];
        let err =
            parse_daemon_config(&args).expect_err("invalid auto-port-forward value should fail");
        assert!(err.contains("invalid auto-port-forward-exit value"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_auto_port_forward_lease() {
        let args = vec![
            "--auto-port-forward-lease-secs".to_string(),
            "0".to_string(),
        ];
        let err = parse_daemon_config(&args).expect_err("zero lease should fail parsing");
        assert!(err.contains("must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_parses_traversal_settings() {
        let args = vec![
            "--traversal-bundle".to_string(),
            "/tmp/rustynet.traversal".to_string(),
            "--traversal-verifier-key".to_string(),
            "/tmp/rustynet.traversal.pub".to_string(),
            "--traversal-watermark".to_string(),
            "/tmp/rustynet.traversal.watermark".to_string(),
            "--traversal-max-age-secs".to_string(),
            "90".to_string(),
            "--traversal-probe-max-candidates".to_string(),
            "4".to_string(),
            "--traversal-probe-max-pairs".to_string(),
            "8".to_string(),
            "--traversal-probe-rounds".to_string(),
            "2".to_string(),
            "--traversal-probe-round-spacing-ms".to_string(),
            "40".to_string(),
            "--traversal-probe-relay-switch-after-failures".to_string(),
            "2".to_string(),
            "--traversal-probe-handshake-freshness-secs".to_string(),
            "15".to_string(),
            "--traversal-probe-reprobe-interval-secs".to_string(),
            "45".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.traversal_bundle_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal")
        );
        assert_eq!(
            config.traversal_verifier_key_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal.pub")
        );
        assert_eq!(
            config.traversal_watermark_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal.watermark")
        );
        assert_eq!(config.traversal_max_age_secs.get(), 90);
        assert_eq!(config.traversal_probe_max_candidates.get(), 4);
        assert_eq!(config.traversal_probe_max_pairs.get(), 8);
        assert_eq!(config.traversal_probe_simultaneous_open_rounds.get(), 2);
        assert_eq!(config.traversal_probe_round_spacing_ms.get(), 40);
        assert_eq!(config.traversal_probe_relay_switch_after_failures.get(), 2);
        assert_eq!(config.traversal_probe_handshake_freshness_secs.get(), 15);
        assert_eq!(config.traversal_probe_reprobe_interval_secs.get(), 45);
    }

    #[test]
    fn parse_daemon_config_parses_dns_zone_settings() {
        let args = vec![
            "--dns-zone-bundle".to_string(),
            "/tmp/rustynet.dns-zone".to_string(),
            "--dns-zone-verifier-key".to_string(),
            "/tmp/rustynet.dns-zone.pub".to_string(),
            "--dns-zone-watermark".to_string(),
            "/tmp/rustynet.dns-zone.watermark".to_string(),
            "--dns-zone-max-age-secs".to_string(),
            "120".to_string(),
            "--dns-zone-name".to_string(),
            "mesh.rustynet".to_string(),
            "--dns-resolver-bind-addr".to_string(),
            "127.0.0.1:5300".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.dns_zone_bundle_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone")
        );
        assert_eq!(
            config.dns_zone_verifier_key_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone.pub")
        );
        assert_eq!(
            config.dns_zone_watermark_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone.watermark")
        );
        assert_eq!(config.dns_zone_max_age_secs.get(), 120);
        assert_eq!(config.dns_zone_name, "mesh.rustynet");
        assert_eq!(
            config.dns_resolver_bind_addr,
            "127.0.0.1:5300".parse().unwrap()
        );
    }

    #[test]
    fn parse_daemon_config_defaults_dns_zone_settings() {
        let config = parse_daemon_config(&[]).expect("default config should parse");
        assert_eq!(
            config.dns_zone_bundle_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_BUNDLE_PATH)
        );
        assert_eq!(
            config.dns_zone_verifier_key_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH)
        );
        assert_eq!(
            config.dns_zone_watermark_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_WATERMARK_PATH)
        );
        assert_eq!(
            config.dns_zone_max_age_secs.get(),
            DEFAULT_DNS_ZONE_MAX_AGE_SECS
        );
        assert_eq!(config.dns_zone_name, DEFAULT_DNS_ZONE_NAME);
        assert_eq!(
            config.dns_resolver_bind_addr,
            DEFAULT_DNS_RESOLVER_BIND_ADDR.parse().unwrap()
        );
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_max_age() {
        let args = vec!["--traversal-max-age-secs".to_string(), "0".to_string()];
        let err = parse_daemon_config(&args).expect_err("zero traversal max age should fail");
        assert!(err.contains("traversal max age must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_dns_zone_max_age() {
        let args = vec!["--dns-zone-max-age-secs".to_string(), "0".to_string()];
        let err = parse_daemon_config(&args).expect_err("zero dns zone max age should fail");
        assert!(err.contains("dns zone max age must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_rounds() {
        let args = vec!["--traversal-probe-rounds".to_string(), "0".to_string()];
        let err = parse_daemon_config(&args).expect_err("zero traversal probe rounds should fail");
        assert!(err.contains("traversal probe rounds must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_freshness() {
        let args = vec![
            "--traversal-probe-handshake-freshness-secs".to_string(),
            "0".to_string(),
        ];
        let err =
            parse_daemon_config(&args).expect_err("zero traversal probe freshness should fail");
        assert!(err.contains("traversal probe handshake freshness must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_reprobe_interval() {
        let args = vec![
            "--traversal-probe-reprobe-interval-secs".to_string(),
            "0".to_string(),
        ];
        let err = parse_daemon_config(&args)
            .expect_err("zero traversal probe reprobe interval should fail");
        assert!(err.contains("traversal probe reprobe interval must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_parses_remote_ops_auth_settings() {
        let args = vec![
            "--remote-ops-token-verifier-key".to_string(),
            "/tmp/rustynet.remote-ops.pub".to_string(),
            "--remote-ops-expected-subject".to_string(),
            "user:remote-admin".to_string(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.remote_ops_token_verifier_key_path,
            Some(std::path::PathBuf::from("/tmp/rustynet.remote-ops.pub"))
        );
        assert_eq!(config.remote_ops_expected_subject, "user:remote-admin");
    }

    #[test]
    fn parse_daemon_config_defaults_remote_ops_auth_settings() {
        let config = parse_daemon_config(&[]).expect("default config should parse");
        assert_eq!(config.remote_ops_token_verifier_key_path, None);
        assert_eq!(
            config.remote_ops_expected_subject,
            DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT
        );
    }
}
