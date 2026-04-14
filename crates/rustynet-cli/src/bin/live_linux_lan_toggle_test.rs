#![forbid(unsafe_code)]

mod live_lab_support;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use live_lab_support::{
    LiveLabContext, Logger, ensure_dir_secure, repo_root, write_secure_json, write_secure_text,
};
use serde_json::json;

const LAN_TEST_INTERFACE: &str = "rnlan0";
const LAN_TEST_GATEWAY_IP: &str = "192.168.1.1/24";
const LAN_TEST_PROBE_IP: &str = "192.168.1.1";
const LAN_TEST_CIDR: &str = "192.168.1.0/24";
const MAX_TRAVERSAL_COORDINATION_TTL_SECS: u64 = 30;
const DNS_ZONE_NAME: &str = "rustynet";
const DNS_ZONE_ISSUE_DIR: &str = "/run/rustynet/dns-zone-issue-lan-toggle";
const DNS_ZONE_VALID_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue-lan-toggle/valid.dns-zone";
const DNS_ZONE_VERIFIER_REMOTE: &str = "/run/rustynet/dns-zone-issue-lan-toggle/rn-dns-zone.pub";

#[derive(Clone, Copy)]
struct DnsRefreshTarget<'a> {
    host: &'a str,
    node_id: &'a str,
    records_local: &'a Path,
    bundle_local: &'a Path,
}

#[derive(Clone, Copy)]
struct DnsRefreshConfig<'a> {
    signer_host: &'a str,
    dns_verifier_local: &'a Path,
    passphrase_remote: &'a str,
    nodes_spec: &'a str,
    allow_spec: &'a str,
    targets: &'a [DnsRefreshTarget<'a>],
}

#[derive(Clone, Copy)]
struct SignedStateRefreshConfig<'a> {
    traversal: TraversalRefreshConfig<'a>,
    dns: DnsRefreshConfig<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentAuthorityScope {
    node_id: String,
    peer_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedDnsRecordTemplate {
    label: String,
    target_node_id: String,
    ttl_secs: u64,
    aliases: Vec<String>,
}

fn etc_rustynet_install_dir_args() -> [&'static str; 9] {
    [
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "root",
        "-g",
        "rustynetd",
        "/etc/rustynet",
    ]
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut exit_host = String::from("debian@192.168.18.49");
    let mut client_host = String::from("debian@192.168.18.65");
    let mut blind_exit_host = String::from("fedora@192.168.18.51");
    let mut exit_node_id = String::from("exit-49");
    let mut client_node_id = String::from("client-65");
    let mut blind_exit_node_id = String::from("client-51");
    let mut ssh_allow_cidrs = String::from("192.168.18.0/24");
    let mut ssh_identity_file = String::new();
    let mut report_path = root_dir.join("artifacts/phase10/live_linux_lan_toggle_report.json");
    let mut log_path = root_dir.join("artifacts/phase10/source/live_linux_lan_toggle.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = required_value(&args, idx, "--ssh-identity-file")?;
            }
            "--exit-host" => {
                idx += 1;
                exit_host = required_value(&args, idx, "--exit-host")?;
            }
            "--client-host" => {
                idx += 1;
                client_host = required_value(&args, idx, "--client-host")?;
            }
            "--blind-exit-host" => {
                idx += 1;
                blind_exit_host = required_value(&args, idx, "--blind-exit-host")?;
            }
            "--exit-node-id" => {
                idx += 1;
                exit_node_id = required_value(&args, idx, "--exit-node-id")?;
            }
            "--client-node-id" => {
                idx += 1;
                client_node_id = required_value(&args, idx, "--client-node-id")?;
            }
            "--blind-exit-node-id" => {
                idx += 1;
                blind_exit_node_id = required_value(&args, idx, "--blind-exit-node-id")?;
            }
            "--ssh-allow-cidrs" => {
                idx += 1;
                ssh_allow_cidrs = required_value(&args, idx, "--ssh-allow-cidrs")?;
            }
            "--report-path" => {
                idx += 1;
                report_path = PathBuf::from(required_value(&args, idx, "--report-path")?);
            }
            "--log-path" => {
                idx += 1;
                log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                return Err(2);
            }
        }
        idx += 1;
    }

    if ssh_identity_file.is_empty() {
        print_usage();
        return Err(2);
    }

    if let Some(parent) = report_path.parent() {
        ensure_dir_secure(parent).map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    }
    if let Some(parent) = log_path.parent() {
        ensure_dir_secure(parent).map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    }

    let logger = Logger::new(&log_path).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let mut ctx = LiveLabContext::new(
        "rustynet-lan-toggle",
        PathBuf::from(&ssh_identity_file).as_path(),
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let mut cleanup = LanToggleCleanup {
        ctx: ctx.clone(),
        exit_host: exit_host.clone(),
        dns_passphrase_remote: None,
    };

    for host in [&exit_host, &client_host, &blind_exit_host] {
        ctx.push_sudo_password(host).map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    }

    logger
        .line("Collecting WireGuard public keys")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let exit_pub_hex = ctx.collect_pubkey_hex(&exit_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let client_pub_hex = ctx.collect_pubkey_hex(&client_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let blind_exit_pub_hex = ctx.collect_pubkey_hex(&blind_exit_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let exit_addr = LiveLabContext::resolved_target_address(&exit_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let client_addr = LiveLabContext::resolved_target_address(&client_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let blind_exit_addr =
        LiveLabContext::resolved_target_address(&blind_exit_host).map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let nodes_spec = format!(
        "{exit_node_id}|{exit_addr}:51820|{exit_pub_hex};{client_node_id}|{client_addr}:51820|{client_pub_hex};{blind_exit_node_id}|{blind_exit_addr}:51820|{blind_exit_pub_hex}"
    );
    let allow_spec = format!(
        "{client_node_id}|{exit_node_id};{exit_node_id}|{client_node_id};{blind_exit_node_id}|{exit_node_id};{exit_node_id}|{blind_exit_node_id}"
    );

    let issue_env = ctx.work_dir.join("rn_issue_lan.env");
    let assignments_spec =
        format!("{exit_node_id}|-;{client_node_id}|{exit_node_id};{blind_exit_node_id}|-");
    write_assignment_env(
        &issue_env,
        &[
            ("NODES_SPEC", &nodes_spec),
            ("ALLOW_SPEC", &allow_spec),
            ("ASSIGNMENTS_SPEC", &assignments_spec),
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    logger
        .line(format!(
            "Issuing signed LAN-toggle assignments on {exit_host}"
        ))
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    issue_assignment_bundles_from_env(&ctx, &exit_host, &issue_env, "/tmp/rn_issue_lan.env")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let assign_pub_local = ctx.work_dir.join("assignment.pub");
    let exit_assignment_local = ctx.work_dir.join("assignment-exit");
    let client_assignment_local = ctx.work_dir.join("assignment-client");
    let blind_exit_assignment_local = ctx.work_dir.join("assignment-blind-exit");
    capture_remote_file(
        &ctx,
        &exit_host,
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        &assign_pub_local,
    )?;
    capture_remote_file(
        &ctx,
        &exit_host,
        &format!("/run/rustynet/assignment-issue/rn-assignment-{exit_node_id}.assignment"),
        &exit_assignment_local,
    )?;
    capture_remote_file(
        &ctx,
        &exit_host,
        &format!("/run/rustynet/assignment-issue/rn-assignment-{client_node_id}.assignment"),
        &client_assignment_local,
    )?;
    capture_remote_file(
        &ctx,
        &exit_host,
        &format!("/run/rustynet/assignment-issue/rn-assignment-{blind_exit_node_id}.assignment"),
        &blind_exit_assignment_local,
    )?;
    let exit_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&exit_assignment_local)
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?
            .as_str(),
    )?;
    let client_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&client_assignment_local)
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?
            .as_str(),
    )?;
    let blind_exit_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&blind_exit_assignment_local)
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?
            .as_str(),
    )?;

    logger
        .line("Distributing signed assignments")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    install_assignment_bundle(&ctx, &exit_host, &assign_pub_local, &exit_assignment_local)?;
    install_assignment_bundle(
        &ctx,
        &client_host,
        &assign_pub_local,
        &client_assignment_local,
    )?;
    install_assignment_bundle(
        &ctx,
        &blind_exit_host,
        &assign_pub_local,
        &blind_exit_assignment_local,
    )?;

    let exit_refresh_local = ctx.work_dir.join("assignment-refresh-exit.env");
    let client_refresh_local = ctx.work_dir.join("assignment-refresh-client.env");
    let blind_exit_refresh_local = ctx.work_dir.join("assignment-refresh-blind-exit.env");
    write_assignment_refresh_env(
        &exit_refresh_local,
        &exit_node_id,
        &nodes_spec,
        &allow_spec,
        None,
    )?;
    write_assignment_refresh_env(
        &client_refresh_local,
        &client_node_id,
        &nodes_spec,
        &allow_spec,
        Some(&exit_node_id),
    )?;
    write_assignment_refresh_env(
        &blind_exit_refresh_local,
        &blind_exit_node_id,
        &nodes_spec,
        &allow_spec,
        None,
    )?;
    install_assignment_refresh_env(&ctx, &exit_host, &exit_refresh_local)?;
    install_assignment_refresh_env(&ctx, &client_host, &client_refresh_local)?;
    install_assignment_refresh_env(&ctx, &blind_exit_host, &blind_exit_refresh_local)?;

    let traversal_env = ctx.work_dir.join("rn_issue_lan_traversal.env");
    write_assignment_env(
        &traversal_env,
        &[("NODES_SPEC", &nodes_spec), ("ALLOW_SPEC", &allow_spec)],
    )?;
    let traversal_pub_local = ctx.work_dir.join("traversal.pub");
    let exit_traversal_local = ctx.work_dir.join("traversal-exit");
    let client_traversal_local = ctx.work_dir.join("traversal-client");
    let blind_exit_traversal_local = ctx.work_dir.join("traversal-blind-exit");
    let dns_verifier_local = ctx.work_dir.join("dns-zone.pub");
    let exit_dns_records_local = ctx.work_dir.join("dns-zone-records-exit.manifest");
    let client_dns_records_local = ctx.work_dir.join("dns-zone-records-client.manifest");
    let blind_exit_dns_records_local = ctx.work_dir.join("dns-zone-records-blind-exit.manifest");
    let exit_dns_local = ctx.work_dir.join("dns-zone-exit");
    let client_dns_local = ctx.work_dir.join("dns-zone-client");
    let blind_exit_dns_local = ctx.work_dir.join("dns-zone-blind-exit");
    let dns_base_records =
        managed_dns_base_records(&exit_node_id, &client_node_id, &blind_exit_node_id);
    write_secure_text(
        &exit_dns_records_local,
        &managed_dns_records_manifest_for_scope(&dns_base_records, &exit_scope)?,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_secure_text(
        &client_dns_records_local,
        &managed_dns_records_manifest_for_scope(&dns_base_records, &client_scope)?,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_secure_text(
        &blind_exit_dns_records_local,
        &managed_dns_records_manifest_for_scope(&dns_base_records, &blind_exit_scope)?,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let dns_passphrase_remote = ctx
        .capture_root(
            &exit_host,
            &["mktemp", "/tmp/rn-lan-toggle-dns-passphrase.XXXXXX"],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?
        .trim()
        .to_string();
    ctx.run_root(
        &exit_host,
        &[
            "rustynet",
            "ops",
            "materialize-signing-passphrase",
            "--output",
            dns_passphrase_remote.as_str(),
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(
        &exit_host,
        &["chmod", "0600", dns_passphrase_remote.as_str()],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(
        &exit_host,
        &["install", "-d", "-m", "0700", DNS_ZONE_ISSUE_DIR],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    cleanup.dns_passphrase_remote = Some(dns_passphrase_remote.clone());
    let traversal_refresh = TraversalRefreshConfig {
        signer_host: exit_host.as_str(),
        exit_host: exit_host.as_str(),
        client_host: client_host.as_str(),
        blind_exit_host: blind_exit_host.as_str(),
        traversal_env: traversal_env.as_path(),
        traversal_pub_local: traversal_pub_local.as_path(),
        exit_traversal_local: exit_traversal_local.as_path(),
        client_traversal_local: client_traversal_local.as_path(),
        blind_exit_traversal_local: blind_exit_traversal_local.as_path(),
        exit_node_id: exit_node_id.as_str(),
        client_node_id: client_node_id.as_str(),
        blind_exit_node_id: blind_exit_node_id.as_str(),
    };
    let dns_targets = [
        DnsRefreshTarget {
            host: exit_host.as_str(),
            node_id: exit_node_id.as_str(),
            records_local: exit_dns_records_local.as_path(),
            bundle_local: exit_dns_local.as_path(),
        },
        DnsRefreshTarget {
            host: client_host.as_str(),
            node_id: client_node_id.as_str(),
            records_local: client_dns_records_local.as_path(),
            bundle_local: client_dns_local.as_path(),
        },
        DnsRefreshTarget {
            host: blind_exit_host.as_str(),
            node_id: blind_exit_node_id.as_str(),
            records_local: blind_exit_dns_records_local.as_path(),
            bundle_local: blind_exit_dns_local.as_path(),
        },
    ];
    let signed_state_refresh = SignedStateRefreshConfig {
        traversal: traversal_refresh,
        dns: DnsRefreshConfig {
            signer_host: exit_host.as_str(),
            dns_verifier_local: dns_verifier_local.as_path(),
            passphrase_remote: dns_passphrase_remote.as_str(),
            nodes_spec: nodes_spec.as_str(),
            allow_spec: allow_spec.as_str(),
            targets: &dns_targets,
        },
    };
    logger
        .line("Issuing and distributing fresh signed traversal bundles for LAN-toggle topology")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;

    logger.line("Enforcing runtime roles").map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    enforce_host(&ctx, &exit_host, "admin", &exit_node_id, &ssh_allow_cidrs)?;
    enforce_host(
        &ctx,
        &client_host,
        "client",
        &client_node_id,
        &ssh_allow_cidrs,
    )?;
    enforce_host(
        &ctx,
        &blind_exit_host,
        "blind_exit",
        &blind_exit_node_id,
        &ssh_allow_cidrs,
    )?;
    ensure_daemon_services_ready(&ctx, &exit_host)?;
    ensure_daemon_services_ready(&ctx, &client_host)?;
    ensure_daemon_services_ready(&ctx, &blind_exit_host)?;

    logger
        .line("Advertising default route on exit")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.retry_root(
        &exit_host,
        &["rustynet", "route", "advertise", "0.0.0.0/0"],
        10,
        2,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    logger
        .line("Provisioning synthetic LAN subnet on exit")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let _ = ctx.run_root_allow_failure(
        &exit_host,
        &["ip", "link", "add", LAN_TEST_INTERFACE, "type", "dummy"],
    );
    ctx.run_root(
        &exit_host,
        &[
            "ip",
            "addr",
            "replace",
            LAN_TEST_GATEWAY_IP,
            "dev",
            LAN_TEST_INTERFACE,
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(&exit_host, &["ip", "link", "set", LAN_TEST_INTERFACE, "up"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    let client_status_off_initial = ctx
        .capture_root(&client_host, &["rustynet", "status"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Initial client status", &client_status_off_initial)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    let mut last_traversal_refresh_unix = unix_now();
    apply_lan_access(&ctx, &client_host, false, LAN_TEST_CIDR)?;
    let lan_off_state = wait_for_lan_access_state(
        &ctx,
        &logger,
        &signed_state_refresh,
        &mut last_traversal_refresh_unix,
        &client_host,
        false,
        45,
    )?;
    let lan_off_ping_status = wait_for_lan_probe_state(
        &ctx,
        &logger,
        &signed_state_refresh,
        &mut last_traversal_refresh_unix,
        &client_host,
        "blocked",
        45,
    )?;
    let client_status_off = ctx
        .capture_root(&client_host, &["rustynet", "status"])
        .unwrap_or_default();

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    last_traversal_refresh_unix = unix_now();
    apply_lan_access(&ctx, &client_host, true, LAN_TEST_CIDR)?;
    let lan_on_state = wait_for_lan_access_state(
        &ctx,
        &logger,
        &signed_state_refresh,
        &mut last_traversal_refresh_unix,
        &client_host,
        true,
        60,
    )?;
    let lan_on_ping_status = if lan_on_state {
        wait_for_lan_probe_state(
            &ctx,
            &logger,
            &signed_state_refresh,
            &mut last_traversal_refresh_unix,
            &client_host,
            "reachable",
            45,
        )?
    } else {
        false
    };
    let client_status_on = ctx
        .capture_root(&client_host, &["rustynet", "status"])
        .unwrap_or_default();
    let client_route_on = ctx
        .capture(
            &client_host,
            &["ip", "-4", "route", "get", LAN_TEST_PROBE_IP],
        )
        .unwrap_or_default();

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    last_traversal_refresh_unix = unix_now();
    apply_lan_access(&ctx, &client_host, false, LAN_TEST_CIDR)?;
    let lan_off_again_state = wait_for_lan_access_state(
        &ctx,
        &logger,
        &signed_state_refresh,
        &mut last_traversal_refresh_unix,
        &client_host,
        false,
        45,
    )?;
    let lan_off_again_status = wait_for_lan_probe_state(
        &ctx,
        &logger,
        &signed_state_refresh,
        &mut last_traversal_refresh_unix,
        &client_host,
        "blocked",
        45,
    )?;
    let client_status_off_final = ctx
        .capture_root(&client_host, &["rustynet", "status"])
        .unwrap_or_default();

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    let blind_exit_denied_status =
        if apply_lan_access_expect_denied(&ctx, &blind_exit_host, true, LAN_TEST_CIDR)? {
            "pass"
        } else {
            "fail"
        };
    let blind_exit_status = ctx
        .capture_root(&blind_exit_host, &["rustynet", "status"])
        .unwrap_or_default();

    let client_plaintext_check = no_plaintext_passphrase_check(&ctx, &client_host)?;
    let exit_plaintext_check = no_plaintext_passphrase_check(&ctx, &exit_host)?;
    let blind_exit_plaintext_check = no_plaintext_passphrase_check(&ctx, &blind_exit_host)?;

    logger
        .block("Client status after LAN on", &client_status_on)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Client status after first LAN off", &client_status_off)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Client route to LAN probe after LAN on", &client_route_on)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Client status after LAN off", &client_status_off_final)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Blind exit status", &blind_exit_status)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let check_lan_off_blocks = if lan_off_state && lan_off_ping_status {
        "pass"
    } else {
        "fail"
    };
    let check_lan_on_allows = if lan_on_state
        && lan_on_ping_status
        && client_status_on.contains("lan_access=on")
        && client_route_on.contains("dev rustynet0")
    {
        "pass"
    } else {
        "fail"
    };
    let check_lan_off_again_blocks = if lan_off_again_state && lan_off_again_status {
        "pass"
    } else {
        "fail"
    };
    let check_client_status_initial_off = if client_status_off_initial.contains("lan_access=off")
        && client_status_off_initial.contains(&format!("exit_node={exit_node_id}"))
    {
        "pass"
    } else {
        "fail"
    };
    let check_client_status_on = if client_status_on.contains("lan_access=on") {
        "pass"
    } else {
        "fail"
    };
    let check_client_status_off = if client_status_off_final.contains("lan_access=off") {
        "pass"
    } else {
        "fail"
    };
    let check_blind_exit_denied = if blind_exit_denied_status == "pass"
        && blind_exit_status.contains("node_role=blind_exit")
        && blind_exit_status.contains("lan_access=off")
    {
        "pass"
    } else {
        "fail"
    };
    let check_no_plaintext_passphrases = if client_plaintext_check
        == "no-plaintext-passphrase-files"
        && exit_plaintext_check == "no-plaintext-passphrase-files"
        && blind_exit_plaintext_check == "no-plaintext-passphrase-files"
    {
        "pass"
    } else {
        "fail"
    };

    let overall = if [
        check_lan_off_blocks,
        check_lan_on_allows,
        check_lan_off_again_blocks,
        check_client_status_initial_off,
        check_client_status_on,
        check_client_status_off,
        check_blind_exit_denied,
        check_no_plaintext_passphrases,
    ]
    .iter()
    .all(|value| *value == "pass")
    {
        "pass"
    } else {
        "fail"
    };

    let captured_at_unix = now_unix();
    let git_commit = git_commit(&root_dir);
    let report = json!({
        "phase": "phase10",
        "mode": "live_linux_lan_toggle",
        "evidence_mode": "measured",
        "captured_at": captured_at_unix,
        "captured_at_unix": captured_at_unix.parse::<u64>().unwrap_or(0),
        "git_commit": git_commit,
        "status": overall,
        "exit_host": exit_host,
        "client_host": client_host,
        "blind_exit_host": blind_exit_host,
        "checks": {
            "lan_off_blocks": check_lan_off_blocks,
            "lan_on_allows": check_lan_on_allows,
            "lan_off_again_blocks": check_lan_off_again_blocks,
            "client_status_initial_off": check_client_status_initial_off,
            "client_status_on": check_client_status_on,
            "client_status_off": check_client_status_off,
            "blind_exit_denied": check_blind_exit_denied,
            "no_plaintext_passphrase_files": check_no_plaintext_passphrases,
        },
        "source_artifacts": [log_path.to_string_lossy().to_string()],
    });
    write_secure_json(&report_path, &report).map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    logger
        .line(format!(
            "LAN toggle report written: {}",
            report_path.display()
        ))
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    if overall != "pass" {
        return Err(1);
    }
    Ok(())
}

struct LanToggleCleanup {
    ctx: LiveLabContext,
    exit_host: String,
    dns_passphrase_remote: Option<String>,
}

impl Drop for LanToggleCleanup {
    fn drop(&mut self) {
        let _ = self.ctx.run_root_allow_failure(
            &self.exit_host,
            &["ip", "link", "delete", LAN_TEST_INTERFACE],
        );
        if let Some(path) = self.dns_passphrase_remote.as_deref() {
            let _ = self
                .ctx
                .run_root_allow_failure(&self.exit_host, &["rm", "-f", path]);
        }
        let _ = self
            .ctx
            .run_root_allow_failure(&self.exit_host, &["rm", "-f", DNS_ZONE_VALID_BUNDLE_REMOTE]);
        let _ = self
            .ctx
            .run_root_allow_failure(&self.exit_host, &["rm", "-f", DNS_ZONE_VERIFIER_REMOTE]);
        let _ = self
            .ctx
            .run_root_allow_failure(&self.exit_host, &["rmdir", DNS_ZONE_ISSUE_DIR]);
    }
}

fn apply_lan_access(
    ctx: &LiveLabContext,
    target: &str,
    enable: bool,
    lan_routes: &str,
) -> Result<(), i32> {
    let output = run_lan_access_command(ctx, target, enable, lan_routes, 20)?;
    if output.status.success() {
        Ok(())
    } else {
        eprintln!(
            "apply-lan-access-coupling failed on {target}: {}",
            summarize_command_output(&output)
        );
        Err(1)
    }
}

fn wait_for_lan_probe_state(
    ctx: &LiveLabContext,
    logger: &Logger,
    refresh_config: &SignedStateRefreshConfig<'_>,
    last_traversal_refresh_unix: &mut u64,
    target: &str,
    desired_state: &str,
    attempts: u32,
) -> Result<bool, i32> {
    for _ in 0..attempts {
        maybe_refresh_signed_state_artifacts(
            ctx,
            logger,
            refresh_config,
            last_traversal_refresh_unix,
        )?;
        let reachable = ctx
            .run(target, &["ping", "-c", "1", "-W", "1", LAN_TEST_PROBE_IP])
            .is_ok();
        if desired_state == "reachable" && reachable {
            return Ok(true);
        }
        if desired_state == "blocked" && !reachable {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(false)
}

fn apply_lan_access_expect_denied(
    ctx: &LiveLabContext,
    target: &str,
    enable: bool,
    lan_routes: &str,
) -> Result<bool, i32> {
    let output = run_lan_access_command(ctx, target, enable, lan_routes, 20)?;
    if output.status.success() {
        return Ok(false);
    }
    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if combined.contains("LAN access coupling is not permitted for blind_exit role") {
        Ok(true)
    } else {
        eprintln!(
            "unexpected blind-exit LAN coupling failure on {target}: {}",
            summarize_command_output(&output)
        );
        Err(1)
    }
}

fn run_lan_access_command(
    ctx: &LiveLabContext,
    target: &str,
    enable: bool,
    lan_routes: &str,
    socket_wait_attempts: u32,
) -> Result<Output, i32> {
    ctx.wait_for_daemon_socket(
        target,
        "/run/rustynet/rustynetd.sock",
        socket_wait_attempts,
        1,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let enable_flag = if enable { "true" } else { "false" };
    let mut args = vec![
        "rustynet",
        "ops",
        "apply-lan-access-coupling",
        "--enable",
        enable_flag,
        "--env-path",
        "/etc/rustynet/assignment-refresh.env",
    ];
    if !lan_routes.is_empty() {
        args.push("--lan-routes");
        args.push(lan_routes);
    }
    ctx.run_root_allow_failure(target, &args).map_err(|err| {
        eprintln!("{err}");
        1
    })
}

fn summarize_command_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr} (stdout: {stdout})")
    } else if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no output".to_string()
    }
}

fn wait_for_lan_access_state(
    ctx: &LiveLabContext,
    logger: &Logger,
    refresh_config: &SignedStateRefreshConfig<'_>,
    last_traversal_refresh_unix: &mut u64,
    target: &str,
    expected_enabled: bool,
    attempts: u32,
) -> Result<bool, i32> {
    let expected = if expected_enabled {
        "lan_access=on"
    } else {
        "lan_access=off"
    };
    for _ in 0..attempts {
        maybe_refresh_signed_state_artifacts(
            ctx,
            logger,
            refresh_config,
            last_traversal_refresh_unix,
        )?;
        if let Ok(status) = ctx.capture_root(target, &["rustynet", "status"])
            && status.contains(expected)
        {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(false)
}

fn no_plaintext_passphrase_check(ctx: &LiveLabContext, target: &str) -> Result<String, i32> {
    let checks = [
        "/var/lib/rustynet/keys/wireguard.passphrase",
        "/etc/rustynet/wireguard.passphrase",
        "/etc/rustynet/signing_key_passphrase",
    ];
    for check in checks {
        ctx.run_root(target, &["test", "!", "-e", check])
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
    }
    Ok("no-plaintext-passphrase-files".to_string())
}

fn write_assignment_env(path: &Path, items: &[(&str, &str)]) -> Result<(), i32> {
    let mut contents = String::new();
    for (key, value) in items {
        contents.push_str(key);
        contents.push('=');
        contents.push_str(&quote_env_value(value)?);
        contents.push('\n');
    }
    write_secure_text(path, &contents).map_err(|err| {
        eprintln!("{err}");
        1
    })
}

fn quote_env_value(value: &str) -> Result<String, i32> {
    if value.chars().any(|ch| ch == '\n' || ch == '\r') {
        eprintln!("env value contains newline characters");
        return Err(1);
    }
    let mut escaped = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            '`' => escaped.push_str("\\`"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn write_assignment_refresh_env(
    path: &Path,
    target_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
    exit_node_id: Option<&str>,
) -> Result<(), i32> {
    let mut items = vec![
        ("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID", target_node_id),
        ("RUSTYNET_ASSIGNMENT_NODES", nodes_spec),
        ("RUSTYNET_ASSIGNMENT_ALLOW", allow_spec),
        (
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
            "/etc/rustynet/assignment.signing.secret",
        ),
        (
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE",
            "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase",
        ),
        ("RUSTYNET_ASSIGNMENT_TTL_SECS", "300"),
        ("RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS", "180"),
    ];
    let exit_node_storage;
    if let Some(exit_node_id) = exit_node_id {
        exit_node_storage = exit_node_id.to_string();
        items.push(("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", &exit_node_storage));
    }
    write_assignment_env(path, &items)
}

fn capture_remote_file(
    ctx: &LiveLabContext,
    target: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), i32> {
    let contents = ctx
        .capture_root(target, &["cat", remote_path])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    write_secure_text(local_path, &contents).map_err(|err| {
        eprintln!("{err}");
        1
    })
}

fn install_assignment_bundle(
    ctx: &LiveLabContext,
    target: &str,
    pubkey_local: &Path,
    bundle_local: &Path,
) -> Result<(), i32> {
    ctx.scp_to(pubkey_local, target, "/tmp/rn-assignment.pub")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-assignment.bundle")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "rustynetd",
            "-g",
            "root",
            "/tmp/rn-assignment.pub",
            "/etc/rustynet/assignment.pub",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            "rustynetd",
            "/tmp/rn-assignment.bundle",
            "/var/lib/rustynet/rustynetd.assignment",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(
        target,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.assignment.watermark",
            "/tmp/rn-assignment.pub",
            "/tmp/rn-assignment.bundle",
        ],
    );
    Ok(())
}

fn install_assignment_refresh_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
) -> Result<(), i32> {
    ctx.scp_to(env_local, target, "/tmp/rn-assignment-refresh.env")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0600",
            "-o",
            "root",
            "-g",
            "root",
            "/tmp/rn-assignment-refresh.env",
            "/etc/rustynet/assignment-refresh.env",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", "/tmp/rn-assignment-refresh.env"]);
    Ok(())
}

fn install_traversal_bundle(
    ctx: &LiveLabContext,
    target: &str,
    pubkey_local: &Path,
    bundle_local: &Path,
) -> Result<(), i32> {
    ctx.scp_to(pubkey_local, target, "/tmp/rn-traversal.pub")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-traversal.bundle")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            "/tmp/rn-traversal.pub",
            "/etc/rustynet/traversal.pub",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            "rustynetd",
            "/tmp/rn-traversal.bundle",
            "/var/lib/rustynet/rustynetd.traversal",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(
        target,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.traversal.watermark",
            "/tmp/rn-traversal.pub",
            "/tmp/rn-traversal.bundle",
        ],
    );
    Ok(())
}

fn install_dns_zone_bundle(
    ctx: &LiveLabContext,
    target: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), i32> {
    ctx.scp_to(verifier_local, target, "/tmp/rn-dns-zone.pub")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-dns-zone.bundle")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            "/tmp/rn-dns-zone.pub",
            "/etc/rustynet/dns-zone.pub",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(
        target,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            "rustynetd",
            "/tmp/rn-dns-zone.bundle",
            "/var/lib/rustynet/rustynetd.dns-zone",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(
        target,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.dns-zone.watermark",
            "/tmp/rn-dns-zone.pub",
            "/tmp/rn-dns-zone.bundle",
        ],
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct TraversalRefreshConfig<'a> {
    signer_host: &'a str,
    exit_host: &'a str,
    client_host: &'a str,
    blind_exit_host: &'a str,
    traversal_env: &'a Path,
    traversal_pub_local: &'a Path,
    exit_traversal_local: &'a Path,
    client_traversal_local: &'a Path,
    blind_exit_traversal_local: &'a Path,
    exit_node_id: &'a str,
    client_node_id: &'a str,
    blind_exit_node_id: &'a str,
}

fn refresh_signed_state_artifacts(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &SignedStateRefreshConfig<'_>,
) -> Result<(), i32> {
    refresh_traversal_bundles(ctx, logger, &config.traversal)?;
    refresh_dns_zone_bundles(ctx, logger, &config.dns)?;
    for target in config.dns.targets {
        refresh_trust_evidence(ctx, target.host)?;
        refresh_signed_state_now(ctx, target.host)?;
    }
    Ok(())
}

fn refresh_traversal_bundles(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &TraversalRefreshConfig<'_>,
) -> Result<(), i32> {
    logger
        .line("Refreshing signed traversal bundles for LAN-toggle participants")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    issue_traversal_bundles_from_env(
        ctx,
        config.signer_host,
        config.traversal_env,
        "/tmp/rn_issue_lan_traversal.env",
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        "/run/rustynet/traversal-issue/rn-traversal.pub",
        config.traversal_pub_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.exit_node_id
        ),
        config.exit_traversal_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.client_node_id
        ),
        config.client_traversal_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.blind_exit_node_id
        ),
        config.blind_exit_traversal_local,
    )?;
    install_traversal_bundle(
        ctx,
        config.exit_host,
        config.traversal_pub_local,
        config.exit_traversal_local,
    )?;
    install_traversal_bundle(
        ctx,
        config.client_host,
        config.traversal_pub_local,
        config.client_traversal_local,
    )?;
    install_traversal_bundle(
        ctx,
        config.blind_exit_host,
        config.traversal_pub_local,
        config.blind_exit_traversal_local,
    )?;
    refresh_signed_state(ctx, config.exit_host)?;
    refresh_signed_state(ctx, config.client_host)?;
    refresh_signed_state(ctx, config.blind_exit_host)?;
    Ok(())
}

fn refresh_dns_zone_bundles(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &DnsRefreshConfig<'_>,
) -> Result<(), i32> {
    logger
        .line("Refreshing signed DNS zone bundles for LAN-toggle participants")
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    for target in config.targets {
        let remote_records = format!("/tmp/rn-lan-toggle-dns-records-{}.manifest", target.node_id);
        ctx.scp_to(
            target.records_local,
            config.signer_host,
            remote_records.as_str(),
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        ctx.run_root(
            config.signer_host,
            &[
                "rustynet",
                "dns",
                "zone",
                "issue",
                "--signing-secret",
                "/etc/rustynet/membership.owner.key",
                "--signing-secret-passphrase-file",
                config.passphrase_remote,
                "--subject-node-id",
                target.node_id,
                "--nodes",
                config.nodes_spec,
                "--allow",
                config.allow_spec,
                "--zone-name",
                DNS_ZONE_NAME,
                "--records-manifest",
                remote_records.as_str(),
                "--output",
                DNS_ZONE_VALID_BUNDLE_REMOTE,
                "--verifier-key-output",
                DNS_ZONE_VERIFIER_REMOTE,
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        let _ =
            ctx.run_root_allow_failure(config.signer_host, &["rm", "-f", remote_records.as_str()]);
        capture_remote_file(
            ctx,
            config.signer_host,
            DNS_ZONE_VERIFIER_REMOTE,
            config.dns_verifier_local,
        )?;
        capture_remote_file(
            ctx,
            config.signer_host,
            DNS_ZONE_VALID_BUNDLE_REMOTE,
            target.bundle_local,
        )?;
        install_dns_zone_bundle(
            ctx,
            target.host,
            config.dns_verifier_local,
            target.bundle_local,
        )?;
    }
    Ok(())
}

fn maybe_refresh_signed_state_artifacts(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &SignedStateRefreshConfig<'_>,
    last_traversal_refresh_unix: &mut u64,
) -> Result<(), i32> {
    let now = unix_now();
    if now.saturating_sub(*last_traversal_refresh_unix)
        >= traversal_refresh_interval_secs(MAX_TRAVERSAL_COORDINATION_TTL_SECS)
    {
        refresh_signed_state_artifacts(ctx, logger, config)?;
        *last_traversal_refresh_unix = unix_now();
    }
    Ok(())
}

fn traversal_refresh_interval_secs(coordination_ttl_secs: u64) -> u64 {
    let bounded_ttl_secs = coordination_ttl_secs.clamp(1, MAX_TRAVERSAL_COORDINATION_TTL_SECS);
    std::cmp::max(1, bounded_ttl_secs / 2)
}

fn refresh_signed_state(ctx: &LiveLabContext, target: &str) -> Result<(), i32> {
    ctx.run_root(
        target,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "state",
            "refresh",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })
}

fn refresh_signed_state_now(ctx: &LiveLabContext, target: &str) -> Result<(), i32> {
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    refresh_signed_state(ctx, target)
}

fn refresh_trust_evidence(ctx: &LiveLabContext, target: &str) -> Result<(), i32> {
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(target, &["rustynet", "ops", "refresh-signed-trust"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })
}

fn issue_assignment_bundles_from_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), i32> {
    ctx.scp_to(env_local, target, remote_env_path)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "rustynet",
            "ops",
            "e2e-issue-assignment-bundles-from-env",
            "--env-file",
            remote_env_path,
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", remote_env_path]);
    Ok(())
}

fn issue_traversal_bundles_from_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), i32> {
    ctx.scp_to(env_local, target, remote_env_path)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        target,
        &[
            "rustynet",
            "ops",
            "e2e-issue-traversal-bundles-from-env",
            "--env-file",
            remote_env_path,
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", remote_env_path]);
    Ok(())
}

fn enforce_host(
    ctx: &LiveLabContext,
    target: &str,
    role: &str,
    node_id: &str,
    ssh_allow_cidrs: &str,
) -> Result<(), i32> {
    let src_dir = LiveLabContext::remote_src_dir_for(target);
    ctx.run_root(
        target,
        &[
            "rustynet",
            "ops",
            "e2e-enforce-host",
            "--role",
            role,
            "--node-id",
            node_id,
            "--src-dir",
            &src_dir,
            "--ssh-allow-cidrs",
            ssh_allow_cidrs,
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })
}

fn ensure_daemon_services_ready(ctx: &LiveLabContext, target: &str) -> Result<(), i32> {
    let _ = ctx.run_root_allow_failure(
        target,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    );
    ctx.run_root(
        target,
        &[
            "systemctl",
            "restart",
            "rustynetd-privileged-helper.service",
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.run_root(target, &["systemctl", "restart", "rustynetd.service"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    Ok(())
}

fn managed_dns_base_records(
    exit_node_id: &str,
    client_node_id: &str,
    blind_exit_node_id: &str,
) -> Vec<ManagedDnsRecordTemplate> {
    vec![
        ManagedDnsRecordTemplate {
            label: "exit".to_string(),
            target_node_id: exit_node_id.to_string(),
            ttl_secs: 300,
            aliases: vec!["gateway".to_string()],
        },
        ManagedDnsRecordTemplate {
            label: "client".to_string(),
            target_node_id: client_node_id.to_string(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
        ManagedDnsRecordTemplate {
            label: "blind-exit".to_string(),
            target_node_id: blind_exit_node_id.to_string(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
    ]
}

fn managed_dns_records_manifest_for_scope(
    records: &[ManagedDnsRecordTemplate],
    scope: &AssignmentAuthorityScope,
) -> Result<String, i32> {
    let allowed_targets = scope.peer_node_ids.iter().cloned().collect::<HashSet<_>>();
    let filtered = records
        .iter()
        .filter(|record| {
            record.target_node_id == scope.node_id
                || allowed_targets.contains(&record.target_node_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        eprintln!(
            "managed DNS scope for {} produced no policy-authorized records",
            scope.node_id
        );
        return Err(1);
    }
    let mut manifest = String::new();
    manifest.push_str("version=1\n");
    manifest.push_str(&format!("record_count={}\n", filtered.len()));
    for (index, record) in filtered.iter().enumerate() {
        manifest.push_str(&format!("record.{index}.label={}\n", record.label));
        manifest.push_str(&format!(
            "record.{index}.target_node_id={}\n",
            record.target_node_id
        ));
        manifest.push_str(&format!("record.{index}.ttl_secs={}\n", record.ttl_secs));
        manifest.push_str(&format!(
            "record.{index}.alias_count={}\n",
            record.aliases.len()
        ));
        for (alias_index, alias) in record.aliases.iter().enumerate() {
            manifest.push_str(&format!("record.{index}.alias.{alias_index}={alias}\n"));
        }
    }
    Ok(manifest)
}

fn parse_assignment_authority_scope(bundle: &str) -> Result<AssignmentAuthorityScope, i32> {
    let mut node_id = None;
    let mut peer_node_ids = Vec::new();
    for line in bundle.lines() {
        if let Some(value) = line.strip_prefix("node_id=") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                eprintln!("assignment bundle node_id must not be empty");
                return Err(1);
            }
            node_id = Some(trimmed.to_string());
            continue;
        }
        if let Some((prefix, value)) = line.split_once('=')
            && prefix.starts_with("peer.")
            && prefix.ends_with(".node_id")
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                eprintln!("assignment bundle peer id must not be empty: {prefix}");
                return Err(1);
            }
            peer_node_ids.push(trimmed.to_string());
        }
    }
    peer_node_ids.sort();
    peer_node_ids.dedup();
    match node_id {
        Some(node_id) => Ok(AssignmentAuthorityScope {
            node_id,
            peer_node_ids,
        }),
        None => {
            eprintln!("assignment bundle is missing node_id");
            Err(1)
        }
    }
}

fn git_commit(root_dir: &Path) -> String {
    if let Ok(value) = std::env::var("RUSTYNET_EXPECTED_GIT_COMMIT") {
        return value.trim().to_lowercase();
    }
    let output = std::process::Command::new("git")
        .current_dir(root_dir)
        .args(["rev-parse", "HEAD"])
        .output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase(),
        _ => "unknown".to_string(),
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, i32> {
    if idx >= args.len() {
        eprintln!("missing value for {flag}");
        return Err(2);
    }
    Ok(args[idx].clone())
}

fn print_usage() {
    println!("usage: live_linux_lan_toggle_test.sh --ssh-identity-file <path> [options]");
}

fn now_unix() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        AssignmentAuthorityScope, ManagedDnsRecordTemplate, managed_dns_base_records,
        managed_dns_records_manifest_for_scope, parse_assignment_authority_scope,
    };

    #[test]
    fn traversal_refresh_interval_is_half_coordination_ttl() {
        assert_eq!(super::traversal_refresh_interval_secs(30), 15);
        assert_eq!(super::traversal_refresh_interval_secs(20), 10);
        assert_eq!(super::traversal_refresh_interval_secs(1), 1);
    }

    #[test]
    fn traversal_refresh_interval_caps_large_ttl_values() {
        assert_eq!(
            super::traversal_refresh_interval_secs(120),
            super::MAX_TRAVERSAL_COORDINATION_TTL_SECS / 2
        );
    }

    #[test]
    fn etc_rustynet_install_dir_uses_rustynetd_group_access() {
        assert_eq!(
            super::etc_rustynet_install_dir_args(),
            [
                "install",
                "-d",
                "-m",
                "0750",
                "-o",
                "root",
                "-g",
                "rustynetd",
                "/etc/rustynet",
            ]
        );
    }

    #[test]
    fn parse_assignment_authority_scope_collects_subject_and_peers() {
        let bundle = "node_id=client-1\npeer.0.node_id=exit-1\npeer.1.node_id=client-3\n";
        let scope = parse_assignment_authority_scope(bundle).expect("scope should parse");
        assert_eq!(
            scope,
            AssignmentAuthorityScope {
                node_id: "client-1".to_string(),
                peer_node_ids: vec!["client-3".to_string(), "exit-1".to_string()],
            }
        );
    }

    #[test]
    fn managed_dns_records_manifest_filters_unauthorized_targets() {
        let mut records = managed_dns_base_records("exit-1", "client-1", "client-3");
        records.push(ManagedDnsRecordTemplate {
            label: "blocked".to_string(),
            target_node_id: "client-9".to_string(),
            ttl_secs: 300,
            aliases: Vec::new(),
        });
        let scope = AssignmentAuthorityScope {
            node_id: "client-1".to_string(),
            peer_node_ids: vec!["exit-1".to_string()],
        };
        let manifest = managed_dns_records_manifest_for_scope(&records, &scope)
            .expect("manifest should be filtered to authorized records");
        assert!(manifest.contains("target_node_id=client-1"));
        assert!(manifest.contains("target_node_id=exit-1"));
        assert!(!manifest.contains("target_node_id=client-3"));
        assert!(!manifest.contains("target_node_id=client-9"));
    }
}
