#![forbid(unsafe_code)]

use rustynetd::daemon::{
    DEFAULT_EGRESS_INTERFACE, DEFAULT_MAX_RECONCILE_FAILURES, DEFAULT_MEMBERSHIP_LOG_PATH,
    DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_MEMBERSHIP_WATERMARK_PATH, DEFAULT_NODE_ID,
    DEFAULT_RECONCILE_INTERVAL_MS, DEFAULT_SOCKET_PATH, DEFAULT_STATE_PATH,
    DEFAULT_TRUST_EVIDENCE_PATH, DEFAULT_TRUST_VERIFIER_KEY_PATH, DEFAULT_TRUST_WATERMARK_PATH,
    DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WG_INTERFACE, DEFAULT_WG_KEY_PASSPHRASE_PATH,
    DEFAULT_WG_PUBLIC_KEY_PATH, DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH, DaemonBackendMode,
    DaemonConfig, DaemonDataplaneMode, run_daemon,
};
use rustynetd::key_material::{
    initialize_encrypted_key_material, migrate_existing_private_key_material,
};
use rustynetd::perf;

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
        [cmd, rest @ ..] if cmd == "key" => run_key_command(rest),
        _ => Err(help_text()),
    }
}

fn run_key_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("key subcommand is required (supported: init, migrate)".to_string());
    }
    match args[0].as_str() {
        "init" => run_key_init(&args[1..]),
        "migrate" => run_key_migrate(&args[1..]),
        other => Err(format!("unknown key subcommand: {other}")),
    }
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

    let public = initialize_encrypted_key_material(
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        force,
    )?;

    println!(
        "key init complete: runtime_private_key={} encrypted_private_key={} public_key={} public_key_value={}",
        runtime_path, encrypted_path, public_path, public
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

    let public = migrate_existing_private_key_material(
        std::path::Path::new(&existing_private_key_path),
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        force,
    )?;

    println!(
        "key migrate complete: existing_private_key={} runtime_private_key={} encrypted_private_key={} public_key={} public_key_value={}",
        existing_private_key_path, runtime_path, encrypted_path, public_path, public
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
                    _ => {
                        return Err("invalid backend value: expected linux-wireguard".to_string());
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
            Some(flag) => {
                return Err(format!("unknown daemon argument: {flag}"));
            }
            None => break,
        }
    }
    Ok(config)
}

fn help_text() -> String {
    [
        "rustynetd usage:",
        "  rustynetd daemon [--node-id <id>] [--socket <path>] [--state <path>] [--trust-evidence <path>] [--trust-verifier-key <path>] [--trust-watermark <path>] [--membership-snapshot <path>] [--membership-log <path>] [--membership-watermark <path>] [--backend <linux-wireguard>] [--wg-interface <name>] [--wg-private-key <path>] [--wg-encrypted-private-key <path>] [--wg-key-passphrase <path>] [--wg-public-key <path>] [--egress-interface <name>] [--dataplane-mode <shell|hybrid-native>] [--reconcile-interval-ms <ms>] [--max-reconcile-failures <n>] [--max-requests <n>]",
        "  rustynetd key init [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key migrate --existing-private-key <path> [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd --emit-phase1-baseline <path>",
        "",
        "defaults:",
        &format!("  node_id={DEFAULT_NODE_ID}"),
        &format!("  socket={DEFAULT_SOCKET_PATH}"),
        &format!("  state={DEFAULT_STATE_PATH}"),
        &format!("  trust_evidence={DEFAULT_TRUST_EVIDENCE_PATH}"),
        &format!("  trust_verifier_key={DEFAULT_TRUST_VERIFIER_KEY_PATH}"),
        &format!("  trust_watermark={DEFAULT_TRUST_WATERMARK_PATH}"),
        &format!("  membership_snapshot={DEFAULT_MEMBERSHIP_SNAPSHOT_PATH}"),
        &format!("  membership_log={DEFAULT_MEMBERSHIP_LOG_PATH}"),
        &format!("  membership_watermark={DEFAULT_MEMBERSHIP_WATERMARK_PATH}"),
        &format!("  backend={:?}", DaemonBackendMode::default()),
        &format!("  wg_interface={DEFAULT_WG_INTERFACE}"),
        &format!("  wg_private_key={DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH}"),
        &format!("  wg_encrypted_private_key={DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH}"),
        &format!("  wg_key_passphrase={DEFAULT_WG_KEY_PASSPHRASE_PATH}"),
        &format!("  wg_public_key={DEFAULT_WG_PUBLIC_KEY_PATH}"),
        &format!("  egress_interface={DEFAULT_EGRESS_INTERFACE}"),
        &format!(
            "  dataplane_mode={:?}",
            DaemonDataplaneMode::default()
        ),
        &format!("  reconcile_interval_ms={DEFAULT_RECONCILE_INTERVAL_MS}"),
        &format!("  max_reconcile_failures={DEFAULT_MAX_RECONCILE_FAILURES}"),
    ]
    .join("\n")
}
