#![forbid(unsafe_code)]

use rustynetd::daemon::{
    DEFAULT_EGRESS_INTERFACE, DEFAULT_FAIL_CLOSED_SSH_ALLOW, DEFAULT_MAX_RECONCILE_FAILURES,
    DEFAULT_MEMBERSHIP_LOG_PATH, DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH,
    DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_MEMBERSHIP_WATERMARK_PATH, DEFAULT_NODE_ID,
    DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS, DEFAULT_RECONCILE_INTERVAL_MS, DEFAULT_SOCKET_PATH,
    DEFAULT_STATE_PATH, DEFAULT_TRUST_EVIDENCE_PATH, DEFAULT_TRUST_VERIFIER_KEY_PATH,
    DEFAULT_TRUST_WATERMARK_PATH, DEFAULT_TRUSTED_HELPER_SOCKET_PATH,
    DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WG_INTERFACE, DEFAULT_WG_KEY_PASSPHRASE_PATH,
    DEFAULT_WG_LISTEN_PORT, DEFAULT_WG_PUBLIC_KEY_PATH, DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH,
    DaemonBackendMode, DaemonConfig, DaemonDataplaneMode, NodeRole, run_daemon,
};
use rustynetd::key_material::{
    initialize_encrypted_key_material, migrate_existing_private_key_material,
    store_passphrase_in_os_secure_store,
};
use rustynetd::perf;
use rustynetd::privileged_helper::{PrivilegedHelperConfig, run_privileged_helper};

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
        "key init complete: runtime_private_key={} encrypted_private_key={} public_key={}",
        runtime_path, encrypted_path, public_path
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
        "key migrate complete: existing_private_key={} runtime_private_key={} encrypted_private_key={} public_key={}",
        existing_private_key_path, runtime_path, encrypted_path, public_path
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
                config.auto_tunnel_max_age_secs = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid auto tunnel max age: {err}"))?;
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
                config.privileged_helper_timeout_ms = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid privileged helper timeout: {err}"))?;
                index += 2;
            }
            Some("--max-requests") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-requests requires a value".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid max requests: {err}"))?;
                config.max_requests = Some(parsed);
                index += 2;
            }
            Some("--reconcile-interval-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--reconcile-interval-ms requires a value".to_string())?;
                config.reconcile_interval_ms = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid reconcile interval: {err}"))?;
                index += 2;
            }
            Some("--max-reconcile-failures") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-reconcile-failures requires a value".to_string())?;
                config.max_reconcile_failures = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid max reconcile failures: {err}"))?;
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
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--fail-closed-ssh-allow-cidrs requires a value".to_string())?;
                config.fail_closed_ssh_allow_cidrs = value
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                index += 2;
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

        persist_owner_signing_key(
            std::path::Path::new(&owner_signing_key_path),
            &approver_key_bytes,
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

fn persist_owner_signing_key(
    path: &std::path::Path,
    key_bytes: &[u8; 32],
    force: bool,
) -> Result<(), String> {
    use std::io::{ErrorKind, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use zeroize::Zeroize;

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
            std::fs::remove_file(path).map_err(|err| {
                format!(
                    "failed to remove existing owner signing key {}: {err}",
                    path.display()
                )
            })?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect owner signing key {}: {err}",
                path.display()
            ));
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).map_err(|err| {
        format!(
            "failed to create owner signing key {}: {err}",
            path.display()
        )
    })?;
    let mut encoded = encode_hex(key_bytes);
    encoded.push('\n');
    file.write_all(encoded.as_bytes()).map_err(|err| {
        format!(
            "failed to write owner signing key {}: {err}",
            path.display()
        )
    })?;
    file.sync_all()
        .map_err(|err| format!("failed to sync owner signing key {}: {err}", path.display()))?;
    encoded.zeroize();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to set owner signing key permissions {}: {err}",
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
        "  rustynetd daemon [--node-id <id>] [--node-role <admin|client|blind_exit>] [--socket <path>] [--state <path>] [--trust-evidence <path>] [--trust-verifier-key <path>] [--trust-watermark <path>] [--membership-snapshot <path>] [--membership-log <path>] [--membership-watermark <path>] [--backend <linux-wireguard|macos-wireguard>] [--wg-interface <name>] [--wg-listen-port <1-65535>] [--wg-private-key <path>] [--wg-encrypted-private-key <path>] [--wg-key-passphrase <path>] [--wg-public-key <path>] [--egress-interface <name>] [--dataplane-mode <shell|hybrid-native>] [--privileged-helper-socket <path>] [--privileged-helper-timeout-ms <ms>] [--reconcile-interval-ms <ms>] [--max-reconcile-failures <n>] [--fail-closed-ssh-allow <true|false>] [--fail-closed-ssh-allow-cidrs <cidr[,cidr...]>] [--max-requests <n>]",
        "  rustynetd privileged-helper [--socket <path>] [--allowed-uid <uid>] [--allowed-gid <gid>] [--timeout-ms <ms>]",
        "  rustynetd key init [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key migrate --existing-private-key <path> [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key store-passphrase --passphrase-file <path> [--keychain-account <name>]",
        "  rustynetd membership init [--snapshot <path>] [--log <path>] [--watermark <path>] [--owner-signing-key <path>] [--node-id <id>] [--network-id <id>] [--force]",
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
