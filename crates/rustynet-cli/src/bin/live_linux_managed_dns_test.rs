#![forbid(unsafe_code)]

mod live_lab_support;

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{
    LiveLabContext, LiveLabPlatform, Logger, repo_root, shell_single_quote, write_secure_json,
    write_secure_text,
};
use serde_json::json;

const MANAGED_LABEL: &str = "exit";
const MANAGED_ALIAS: &str = "gateway";
const ISSUE_DIR: &str = "/run/rustynet/dns-zone-issue";
const TRAVERSAL_ISSUE_DIR: &str = "/run/rustynet/traversal-issue";
const DNS_ZONE_PUB_REMOTE: &str = "/run/rustynet/dns-zone-issue/rn-dns-zone.pub";
const DNS_VALID_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/valid.dns-zone";
const DNS_STALE_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/stale.dns-zone";
const DNS_REPLAY_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/replay.dns-zone";
const DNS_POLICY_INVALID_BUNDLE_REMOTE: &str =
    "/run/rustynet/dns-zone-issue/policy-invalid.dns-zone";
const DNS_RECORDS_REMOTE: &str = "/tmp/rn-dns-records.manifest";
const TRAVERSAL_ENV_REMOTE: &str = "/tmp/rn_issue_dns_traversal.env";
const TRAVERSAL_PUB_REMOTE: &str = "/run/rustynet/traversal-issue/rn-traversal.pub";
const REPLAY_PROBE_ALIAS: &str = "gatewayreplay";
// 20 attempts × 15 s = 5 min window; tolerates UTM VM transient network
// glitches and slower-than-expected SSH restarts during the extended soak.
const SOAK_SSH_RETRY_ATTEMPTS: u32 = 20;
const SOAK_SSH_RETRY_SLEEP_SECS: u64 = 15;

fn main() {
    if let Err(err) = run() {
        let code = classify_live_lab_error(err.as_str());
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("error [{code}]: {err}");
        } else {
            eprintln!("error [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

/// X6 taxonomy classifier for live-lab test binaries. Mirrors the
/// classifier in `live_linux_exit_handoff_test.rs`.
fn classify_live_lab_error(message: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = message.to_ascii_lowercase();
    if lower.contains("missing required")
        || lower.contains("unknown command")
        || lower.contains("missing required argument")
    {
        ExitCode::BadArgs
    } else if lower.contains("drift")
        || lower.contains("fail-closed")
        || lower.contains("signature verification")
        || lower.contains("policy reject")
        || lower.contains("forbidden")
    {
        ExitCode::PolicyReject
    } else if lower.contains("missing required command")
        || lower.contains("identity file")
        || lower.contains("invalid path")
        || lower.contains("config")
        || lower.contains("schema")
    {
        ExitCode::ConfigError
    } else if lower.contains("ssh")
        || lower.contains("scp")
        || lower.contains("timed out")
        || lower.contains("connection refused")
        || lower.contains("transient")
        || lower.contains("retry")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let root_dir = repo_root()?;
    let config = Config::parse(env::args().skip(1).collect())?;

    // Wave 2 (W2-D): the managed-DNS suite is now cross-OS. `config.platform`
    // is threaded through every resolver-stack command (split-DNS inspection,
    // OS-resolver answer probe, managed-resolver service state) via runtime
    // `match platform` branches — NOT `cfg` — so the binary compiles and
    // unit-tests on this Linux host while still running the real per-OS
    // assertion logic against a macOS or Windows guest. The loopback-resolver
    // direct query stays OS-independent: it uses `rustynet ops e2e-dns-query`,
    // a portable Rust UDP client that speaks raw DNS to 127.0.0.1:53535 on any
    // OS, so the answer / REFUSED-negative / fail-closed-adversarial-guard
    // assertions remain byte-identical across platforms. The old
    // `enforce_linux_only_until_validator_lands` gate is intentionally gone
    // for this binary.
    for command in ["cargo", "git", "ssh", "scp", "ssh-keygen", "date"] {
        require_command(command)?;
    }

    let ssh_identity = PathBuf::from(&config.ssh_identity_file);
    let mut ctx = LiveLabContext::new_with_pinned_known_hosts(
        "rustynet-managed-dns",
        ssh_identity.as_path(),
        config.known_hosts_file.as_deref(),
    )?;
    let logger = Logger::new(&config.log_path)?;

    validate_targets(&config)?;

    logger.line("[managed-dns] starting live managed DNS validation")?;
    for host in [&config.signer_host, &config.client_host] {
        ctx.push_sudo_password(host)?;
    }
    refresh_signer_trust_evidence(&ctx, &config.signer_host)?;

    logger.line("[managed-dns] collecting WireGuard public keys")?;
    let client_status_before = ctx.capture_root(
        &config.client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "status",
        ],
    )?;
    let current_exit_node = parse_status_field(&client_status_before, "exit_node")
        .ok_or_else(|| "unable to parse exit_node from client rustynet status".to_owned())?;
    logger.line(
        format!(
            "[managed-dns] client runtime exit selection before bundle refresh: exit_node={current_exit_node}"
        )
        .as_str(),
    )?;

    let mut host_by_node = HashMap::new();
    host_by_node.insert(config.signer_node_id.clone(), config.signer_host.clone());
    host_by_node.insert(config.client_node_id.clone(), config.client_host.clone());
    // The signer and client are always Linux in this validator; each managed
    // peer carries its own platform parsed from --managed-peer. The platform
    // map locates per-OS state (assignment bundle) and decides which peers can
    // accept the Linux-only bundle re-push.
    let mut platform_by_node: HashMap<String, live_lab_support::LiveLabPlatform> = HashMap::new();
    platform_by_node.insert(
        config.signer_node_id.clone(),
        live_lab_support::LiveLabPlatform::Linux,
    );
    platform_by_node.insert(
        config.client_node_id.clone(),
        live_lab_support::LiveLabPlatform::Linux,
    );
    for peer in &config.managed_peers {
        host_by_node.insert(peer.node_id.clone(), peer.host.clone());
        platform_by_node.insert(peer.node_id.clone(), peer.platform);
    }

    if current_exit_node != "none"
        && current_exit_node != config.signer_node_id
        && current_exit_node != config.client_node_id
        && !host_by_node.contains_key(&current_exit_node)
    {
        return Err(format!(
            "client exit_node {current_exit_node} is not mapped to a host; provide --managed-peer {current_exit_node}|<user@host>"
        ));
    }
    let assignment_scopes =
        capture_assignment_authority_scopes(&ctx, &host_by_node, &platform_by_node)?;

    let mut mesh_peers = Vec::new();
    for (node_id, host) in sorted_node_host_pairs(&host_by_node) {
        mesh_peers.push(ManagedPeerRuntime {
            node_id,
            address: LiveLabContext::resolved_target_address(&host)?,
            pubkey_hex: ctx.collect_pubkey_hex(&host)?,
        });
    }

    let nodes_spec = mesh_peers
        .iter()
        .map(|peer| {
            format!(
                "{}|{}:51820|{}",
                peer.node_id, peer.address, peer.pubkey_hex
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    let allow_spec = build_authorized_allow_spec(&assignment_scopes, &host_by_node)?;
    ensure_safe_spec("NODES_SPEC", &nodes_spec)?;
    ensure_safe_spec("ALLOW_SPEC", &allow_spec)?;

    let workspace = ctx.work_dir.clone();
    let base_records = managed_dns_base_records(&config.signer_node_id, &config.client_node_id);
    let records_manifest = workspace.join("rn-dns-records.manifest");
    let client_scope = assignment_scopes
        .get(&config.client_node_id)
        .ok_or_else(|| {
            format!(
                "missing assignment authority scope for client node {}",
                config.client_node_id
            )
        })?;
    write_secure_text(
        &records_manifest,
        &managed_dns_records_manifest_for_scope(&base_records, client_scope)?,
    )?;

    let issue_dir = ISSUE_DIR;
    let valid_generated_at = unix_now();
    let valid_nonce = valid_generated_at.saturating_mul(2).saturating_add(17);
    let stale_generated_at = valid_generated_at.saturating_sub(7200);
    let stale_nonce = valid_nonce.saturating_sub(1);
    let replay_records = managed_dns_replay_records(&base_records, &config.signer_node_id)?;
    let replay_records_manifest = workspace.join("rn-dns-records-replay.manifest");
    write_secure_text(
        &replay_records_manifest,
        &managed_dns_records_manifest_for_scope(&replay_records, client_scope)?,
    )?;
    let policy_invalid_scope = assignment_scopes
        .get(&config.signer_node_id)
        .ok_or_else(|| {
            format!(
                "missing assignment authority scope for signer node {}",
                config.signer_node_id
            )
        })?;
    let policy_invalid_records_manifest = workspace.join("rn-dns-records-policy-invalid.manifest");
    write_secure_text(
        &policy_invalid_records_manifest,
        &managed_dns_records_manifest_for_scope(&base_records, policy_invalid_scope)?,
    )?;
    let passphrase_file = ctx
        .capture_root(
            &config.signer_host,
            &["mktemp", "/tmp/rn-dns-zone-passphrase.XXXXXX"],
        )?
        .trim()
        .to_owned();
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "ops",
            "materialize-signing-passphrase",
            "--output",
            &passphrase_file,
        ],
    )?;
    ctx.run_root(&config.signer_host, &["chmod", "0600", &passphrase_file])?;
    ctx.run_root(&config.signer_host, &["rm", "-rf", issue_dir])?;
    ctx.run_root(
        &config.signer_host,
        &["install", "-d", "-m", "0700", issue_dir],
    )?;
    ctx.scp_to(&records_manifest, &config.signer_host, DNS_RECORDS_REMOTE)?;
    let replay_records_remote = "/tmp/rn-dns-records-replay.manifest";
    ctx.scp_to(
        &replay_records_manifest,
        &config.signer_host,
        replay_records_remote,
    )?;
    let policy_invalid_records_remote = "/tmp/rn-dns-records-policy-invalid.manifest";
    ctx.scp_to(
        &policy_invalid_records_manifest,
        &config.signer_host,
        policy_invalid_records_remote,
    )?;
    let dns_issue = DnsIssueContext {
        ctx: &ctx,
        signer_host: &config.signer_host,
        passphrase_file: &passphrase_file,
        zone_name: &config.zone_name,
        nodes_spec: &nodes_spec,
        allow_spec: &allow_spec,
        issue_dir,
    };

    logger.line(
        format!(
            "[managed-dns] issuing signed DNS bundles on {}",
            config.signer_host
        )
        .as_str(),
    )?;
    issue_dns_bundle(
        dns_issue,
        DnsBundleSpec {
            subject_node_id: &config.client_node_id,
            records_manifest_remote: DNS_RECORDS_REMOTE,
            output_name: "valid.dns-zone",
            timing: DnsBundleTiming {
                generated_at: Some(valid_generated_at),
                nonce: Some(valid_nonce),
            },
        },
    )?;
    issue_dns_bundle(
        dns_issue,
        DnsBundleSpec {
            subject_node_id: &config.client_node_id,
            records_manifest_remote: DNS_RECORDS_REMOTE,
            output_name: "stale.dns-zone",
            timing: DnsBundleTiming {
                generated_at: Some(stale_generated_at),
                nonce: Some(stale_nonce),
            },
        },
    )?;
    issue_dns_bundle(
        dns_issue,
        DnsBundleSpec {
            subject_node_id: &config.client_node_id,
            records_manifest_remote: replay_records_remote,
            output_name: "replay.dns-zone",
            timing: DnsBundleTiming {
                generated_at: Some(valid_generated_at),
                nonce: Some(valid_nonce),
            },
        },
    )?;
    issue_dns_bundle(
        dns_issue,
        DnsBundleSpec {
            subject_node_id: &config.signer_node_id,
            records_manifest_remote: policy_invalid_records_remote,
            output_name: "policy-invalid.dns-zone",
            timing: DnsBundleTiming {
                generated_at: Some(valid_generated_at.saturating_add(1)),
                nonce: Some(valid_nonce.saturating_add(1)),
            },
        },
    )?;

    let verifier_local = workspace.join("dns-zone.pub");
    let valid_bundle_local = workspace.join("dns-zone-valid.bundle");
    let stale_bundle_local = workspace.join("dns-zone-stale.bundle");
    let replay_bundle_local = workspace.join("dns-zone-replay.bundle");
    let policy_invalid_bundle_local = workspace.join("dns-zone-policy-invalid.bundle");
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_ZONE_PUB_REMOTE,
        &verifier_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_VALID_BUNDLE_REMOTE,
        &valid_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_STALE_BUNDLE_REMOTE,
        &stale_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_REPLAY_BUNDLE_REMOTE,
        &replay_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_POLICY_INVALID_BUNDLE_REMOTE,
        &policy_invalid_bundle_local,
    )?;
    let valid_bundle_wire = std::fs::read_to_string(&valid_bundle_local).map_err(|err| {
        format!(
            "failed to read valid dns bundle {}: {err}",
            valid_bundle_local.display()
        )
    })?;
    let forged_bundle_local = workspace.join("dns-zone-forged.bundle");
    write_secure_text(
        &forged_bundle_local,
        &rewrite_bundle_signature(&valid_bundle_wire, "0")?,
    )?;
    let tampered_bundle_local = workspace.join("dns-zone-tampered.bundle");
    write_secure_text(
        &tampered_bundle_local,
        &rewrite_bundle_line_value(&valid_bundle_wire, "record.0.fqdn", "tampered.rustynet")?,
    )?;

    logger.line("[managed-dns] verifying signed managed DNS bundles on signer host")?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_VALID_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_REPLAY_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_POLICY_INVALID_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.signer_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_STALE_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;

    logger.line(
        format!(
            "[managed-dns] installing valid managed DNS bundle on {}",
            config.client_host
        )
        .as_str(),
    )?;
    install_dns_bundle(
        &ctx,
        &config.client_host,
        &verifier_local,
        &valid_bundle_local,
    )?;
    refresh_traversal_bundles(
        &ctx,
        &config,
        &logger,
        &workspace,
        &host_by_node,
        &platform_by_node,
        &nodes_spec,
        &allow_spec,
    )?;
    restart_managed_dns_stack(&ctx, &config.client_host)?;

    let dns_inspect_valid =
        wait_for_dns_inspect_state(&ctx, &config.client_host, Some("valid"), 20, 2)?;
    // Split-DNS / resolver-configuration inspection. Per-OS command:
    //   Linux   → `resolvectl status <iface>` (systemd-resolved)
    //   macOS   → `scutil --dns` (the System Configuration resolver list)
    //   Windows → `Get-DnsClientServerAddress` (per-interface DNS servers)
    // The captured text is fed to a per-OS pure parser that asserts the
    // managed loopback resolver is the configured DNS server for the mesh.
    let resolver_config_capture =
        capture_resolver_config_status(&ctx, &config.client_host, &config)?;
    // Loopback-resolver direct query. OS-independent: `rustynet ops
    // e2e-dns-query` speaks raw DNS to 127.0.0.1:53535 (the daemon-managed
    // resolver) so the JSON answer/rcode shape — and therefore the answer,
    // REFUSED-negative, and fail-closed assertions — stay byte-identical on
    // every OS.
    let direct_query_valid =
        remote_dns_query_capture(&ctx, &config.client_host, &config, &config.managed_fqdn())?;
    let direct_alias_query_valid = remote_dns_query_capture(
        &ctx,
        &config.client_host,
        &config,
        &config.managed_alias_fqdn(),
    )?;
    let non_managed_direct_query =
        remote_dns_query_capture(&ctx, &config.client_host, &config, "example.com")?;
    flush_os_resolver_cache(&ctx, &config.client_host, &config)?;
    // OS-resolver answer probe. Proves the host's *system* resolver path —
    // not just the loopback UDP client above — returns the managed A record:
    //   Linux   → `resolvectl query` (systemd-resolved)
    //   macOS   → `dig @127.0.0.1 -p 53535` against the managed resolver,
    //             corroborated by `dscacheutil -q host` for the cache view
    //   Windows → `Resolve-DnsName -Server 127.0.0.1`, with `nslookup` as the
    //             secondary check
    let os_resolver_answer_valid =
        capture_os_resolver_answer(&ctx, &config.client_host, &config, &config.managed_fqdn())?;

    let expected_ip =
        extract_managed_dns_expected_ip(&root_dir, &config.managed_fqdn(), &dns_inspect_valid)?;

    logger.block("[managed-dns] valid dns inspect", &dns_inspect_valid)?;
    logger.block(
        format!(
            "[managed-dns] valid resolver config status ({})",
            config.platform.as_str()
        )
        .as_str(),
        &resolver_config_capture,
    )?;
    logger.block(
        "[managed-dns] valid loopback DNS query",
        &direct_query_valid,
    )?;
    logger.block(
        format!(
            "[managed-dns] valid OS resolver answer ({})",
            config.platform.as_str()
        )
        .as_str(),
        &os_resolver_answer_valid,
    )?;
    let validation = ManagedDnsValidationContext {
        logger: &logger,
        root_dir: &root_dir,
        config: &config,
        workspace: &workspace,
        host_by_node: &host_by_node,
        platform_by_node: &platform_by_node,
        verifier_local: &verifier_local,
        dns_issue,
    };

    let stale_case = exercise_invalid_bundle_case(
        validation,
        InvalidBundleCaseSpec {
            bundle_local: &stale_bundle_local,
            clear_watermark: true,
            case_label: "stale",
            expected_reason_fragments: &["stale"],
        },
    )?;

    restore_valid_bundle_after_invalid_case(
        validation,
        RestoreValidBundleSpec {
            valid_bundle_local: &valid_bundle_local,
            output_name: "valid-restore.dns-zone",
        },
    )?;

    let replay_case = exercise_invalid_bundle_case(
        validation,
        InvalidBundleCaseSpec {
            bundle_local: &replay_bundle_local,
            clear_watermark: false,
            case_label: "replay",
            expected_reason_fragments: &["replay detected"],
        },
    )?;
    restore_valid_bundle_after_invalid_case(
        validation,
        RestoreValidBundleSpec {
            valid_bundle_local: &valid_bundle_local,
            output_name: "valid-restore.dns-zone",
        },
    )?;

    let forged_case = exercise_invalid_bundle_case(
        validation,
        InvalidBundleCaseSpec {
            bundle_local: &forged_bundle_local,
            clear_watermark: true,
            case_label: "forged",
            expected_reason_fragments: &["signature verification failed"],
        },
    )?;
    restore_valid_bundle_after_invalid_case(
        validation,
        RestoreValidBundleSpec {
            valid_bundle_local: &valid_bundle_local,
            output_name: "valid-restore.dns-zone",
        },
    )?;

    let tampered_case = exercise_invalid_bundle_case(
        validation,
        InvalidBundleCaseSpec {
            bundle_local: &tampered_bundle_local,
            clear_watermark: true,
            case_label: "tampered",
            expected_reason_fragments: &["invalid format"],
        },
    )?;
    restore_valid_bundle_after_invalid_case(
        validation,
        RestoreValidBundleSpec {
            valid_bundle_local: &valid_bundle_local,
            output_name: "valid-restore.dns-zone",
        },
    )?;

    let policy_invalid_case = exercise_invalid_bundle_case(
        validation,
        InvalidBundleCaseSpec {
            bundle_local: &policy_invalid_bundle_local,
            clear_watermark: true,
            case_label: "policy-invalid",
            expected_reason_fragments: &["subject node id does not match local node"],
        },
    )?;

    // Restore a fresh valid client bundle after the adversarial sequence.
    restore_valid_bundle_after_invalid_case(
        validation,
        RestoreValidBundleSpec {
            valid_bundle_local: &valid_bundle_local,
            output_name: "valid-restore.dns-zone",
        },
    )?;
    let dns_inspect_restored =
        wait_for_dns_inspect_state(&ctx, &config.client_host, Some("valid"), 20, 2)?;

    for (node_id, host) in managed_dns_distribution_targets(&host_by_node, &config.client_host) {
        let node_platform = platform_by_node
            .get(&node_id)
            .copied()
            .ok_or_else(|| format!("missing platform mapping for managed DNS node {node_id}"))?;
        // The Linux re-issue+re-push below uses Linux paths and `-o root -g
        // rustynetd` ownership, which do not exist on macOS/Windows. Those
        // peers already received correct, signed bundles during the setup
        // distribution stages, and the lab daemon max-age is 86400s, so the
        // bundles stay valid for the whole run. Only the client's resolution is
        // asserted, and the client + signer are Linux. Skip non-Linux peers.
        if node_platform != live_lab_support::LiveLabPlatform::Linux {
            logger.line(format!(
                "[managed-dns] skip bundle re-push for non-linux peer {node_id} ({platform}); setup-distributed bundles stay fresh under the 86400s lab window",
                platform = node_platform.as_str()
            ))?;
            continue;
        }
        logger.line(
            format!(
                "[managed-dns] issuing valid managed DNS bundle for {node_id} on {}",
                config.signer_host
            )
            .as_str(),
        )?;
        let scope = assignment_scopes.get(&node_id).ok_or_else(|| {
            format!("missing assignment authority scope for managed DNS node {node_id}")
        })?;
        let peer_records_local = workspace.join(format!("rn-dns-records-{node_id}.manifest"));
        let peer_records_remote = format!("/tmp/rn-dns-records-{node_id}.manifest");
        write_secure_text(
            &peer_records_local,
            &managed_dns_records_manifest_for_scope(&base_records, scope)?,
        )?;
        ctx.scp_to(
            &peer_records_local,
            &config.signer_host,
            peer_records_remote.as_str(),
        )?;

        let output_name = format!("valid-{node_id}.dns-zone");
        issue_dns_bundle(
            dns_issue,
            DnsBundleSpec {
                subject_node_id: &node_id,
                records_manifest_remote: peer_records_remote.as_str(),
                output_name: output_name.as_str(),
                timing: DnsBundleTiming {
                    generated_at: None,
                    nonce: None,
                },
            },
        )?;
        let _ = ctx.run_root_allow_failure(
            &config.signer_host,
            &["rm", "-f", peer_records_remote.as_str()],
        );
        let peer_bundle_local = workspace.join(format!("dns-zone-valid-{node_id}.bundle"));
        let remote_bundle_path = format!("{issue_dir}/{output_name}");
        capture_remote_text(
            &ctx,
            &config.signer_host,
            remote_bundle_path.as_str(),
            &peer_bundle_local,
        )?;
        logger.line(
            format!("[managed-dns] propagating valid managed DNS bundle to {host}").as_str(),
        )?;
        install_dns_bundle(&ctx, &host, &verifier_local, &peer_bundle_local)?;
        if host == config.client_host {
            continue;
        }
        if host == config.signer_host {
            refresh_signer_trust_evidence(&ctx, &host)?;
        }
        restart_managed_dns_stack(&ctx, &host)?;
    }

    let check_zone_issue_verify = "pass";
    let mut check_dns_inspect_valid = "fail";
    let mut check_managed_dns_service_active = "fail";
    let mut check_resolvectl_split_dns = "fail";
    let mut check_loopback_query_valid = "fail";
    let mut check_resolvectl_query_valid = "fail";
    let mut check_alias_query_valid = "fail";
    let mut check_non_managed_refused = "fail";
    let mut check_stale_bundle_fail_closed = "fail";
    let mut check_replayed_bundle_fail_closed = "fail";
    let mut check_forged_bundle_fail_closed = "fail";
    let mut check_tampered_bundle_fail_closed = "fail";
    let mut check_policy_invalid_bundle_fail_closed = "fail";
    let mut check_valid_bundle_restored = "fail";

    if dns_inspect_valid.contains("dns inspect: state=valid")
        && dns_inspect_valid.contains(&format!("zone_name={}", config.zone_name))
    {
        check_dns_inspect_valid = "pass";
    }
    // Managed-resolver service-active check. On Linux the managed resolver
    // runs as the dedicated `rustynetd-managed-dns.service` systemd unit, so
    // `systemctl is-active` is the direct probe. On macOS/Windows there is NO
    // separate managed-DNS service — the resolver is hosted inside the main
    // daemon process (launchd `com.rustynet.daemon` / the `RustyNet` SCM
    // service). The check therefore confirms the *hosting* daemon is live; a
    // dead daemon (= dead managed resolver) fails closed honestly. See the
    // REVIEW note on `capture_managed_dns_service_state`.
    let managed_service_state =
        capture_managed_dns_service_state(&ctx, &config.client_host, &config)?;
    if managed_dns_service_active(config.platform, managed_service_state.as_str()) {
        check_managed_dns_service_active = "pass";
    }
    if resolver_config_advertises_managed_zone(
        config.platform,
        resolver_config_capture.as_str(),
        &config.dns_bind_addr,
        &config.dns_server(),
        &config.zone_name,
    ) {
        check_resolvectl_split_dns = "pass";
    }
    if json_field(&root_dir, &direct_query_valid, "rcode")? == "0"
        && json_field(&root_dir, &direct_query_valid, "answer_ip")? == expected_ip
    {
        check_loopback_query_valid = "pass";
    }
    if json_field(&root_dir, &direct_alias_query_valid, "rcode")? == "0"
        && json_field(&root_dir, &direct_alias_query_valid, "answer_ip")? == expected_ip
    {
        check_alias_query_valid = "pass";
    }
    if os_resolver_answer_contains_ip(
        config.platform,
        os_resolver_answer_valid.as_str(),
        expected_ip.as_str(),
    ) {
        check_resolvectl_query_valid = "pass";
    }
    if json_field(&root_dir, &non_managed_direct_query, "rcode")? == "5" {
        check_non_managed_refused = "pass";
    }

    if stale_case.passed {
        check_stale_bundle_fail_closed = "pass";
    }
    if replay_case.passed {
        check_replayed_bundle_fail_closed = "pass";
    }
    if forged_case.passed {
        check_forged_bundle_fail_closed = "pass";
    }
    if tampered_case.passed {
        check_tampered_bundle_fail_closed = "pass";
    }
    if policy_invalid_case.passed {
        check_policy_invalid_bundle_fail_closed = "pass";
    }
    if dns_inspect_restored.contains("dns inspect: state=valid") {
        check_valid_bundle_restored = "pass";
    }

    let overall = [
        check_zone_issue_verify,
        check_dns_inspect_valid,
        check_managed_dns_service_active,
        check_resolvectl_split_dns,
        check_loopback_query_valid,
        check_resolvectl_query_valid,
        check_alias_query_valid,
        check_non_managed_refused,
        check_stale_bundle_fail_closed,
        check_replayed_bundle_fail_closed,
        check_forged_bundle_fail_closed,
        check_tampered_bundle_fail_closed,
        check_policy_invalid_bundle_fail_closed,
        check_valid_bundle_restored,
    ]
    .into_iter()
    .all(|value| value == "pass");

    let captured_at_utc = utc_now_string();
    let captured_at_unix = unix_now();
    let git_commit = git_commit(&root_dir);

    let report = json!({
        "phase": "phase10",
        "mode": "live_linux_managed_dns",
        "evidence_mode": "measured",
        "captured_at": captured_at_utc,
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": if overall { "pass" } else { "fail" },
        "zone_name": config.zone_name,
        "signer_host": config.signer_host,
        "client_host": config.client_host,
        "managed_fqdn": config.managed_fqdn(),
        "managed_alias_fqdn": config.managed_alias_fqdn(),
        "expected_ip": expected_ip,
        "checks": {
            "zone_issue_verify_passes": check_zone_issue_verify,
            "dns_inspect_valid": check_dns_inspect_valid,
            "managed_dns_service_active": check_managed_dns_service_active,
            "resolvectl_split_dns_configured": check_resolvectl_split_dns,
            "loopback_resolver_answers_managed_name": check_loopback_query_valid,
            "systemd_resolved_answers_managed_name": check_resolvectl_query_valid,
            "alias_resolves_to_expected_ip": check_alias_query_valid,
            "non_managed_query_refused": check_non_managed_refused,
            "stale_bundle_fail_closed": check_stale_bundle_fail_closed,
            "replayed_bundle_fail_closed": check_replayed_bundle_fail_closed,
            "forged_bundle_fail_closed": check_forged_bundle_fail_closed,
            "tampered_bundle_fail_closed": check_tampered_bundle_fail_closed,
            "policy_invalid_bundle_fail_closed": check_policy_invalid_bundle_fail_closed,
            "valid_bundle_restored": check_valid_bundle_restored,
        },
        "source_artifacts": [
            config.log_path.display().to_string(),
        ],
    });
    write_secure_json(&config.report_path, &report)?;

    logger.line(
        format!(
            "[managed-dns] report written: {}",
            config.report_path.display()
        )
        .as_str(),
    )?;

    let _ = ctx.run_root_allow_failure(
        &config.signer_host,
        &[
            "rm",
            "-f",
            DNS_RECORDS_REMOTE,
            replay_records_remote,
            policy_invalid_records_remote,
            &passphrase_file,
        ],
    );
    let _ = ctx.run_root_allow_failure(
        &config.signer_host,
        &["rm", "-rf", issue_dir, TRAVERSAL_ISSUE_DIR],
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    platform: live_lab_support::LiveLabPlatform,
    ssh_identity_file: String,
    signer_host: String,
    client_host: String,
    signer_node_id: String,
    client_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    log_path: PathBuf,
    zone_name: String,
    dns_interface: String,
    dns_bind_addr: String,
    managed_peers: Vec<ManagedPeerSpec>,
    known_hosts_file: Option<PathBuf>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: live_lab_support::LiveLabPlatform::Linux,
            ssh_identity_file: String::new(),
            signer_host: "debian@192.168.18.49".to_owned(),
            client_host: "ubuntu@192.168.18.52".to_owned(),
            signer_node_id: "exit-49".to_owned(),
            client_node_id: "client-52".to_owned(),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            report_path: PathBuf::from("artifacts/phase10/source/managed_dns_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/managed_dns_report.log"),
            zone_name: "rustynet".to_owned(),
            dns_interface: "rustynet0".to_owned(),
            dns_bind_addr: "127.0.0.1:53535".to_owned(),
            managed_peers: Vec::new(),
            known_hosts_file: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform = live_lab_support::LiveLabPlatform::parse(
                        next_value(&mut iter, &arg)?.as_str(),
                    )?;
                }
                "--ssh-identity-file" => config.ssh_identity_file = next_value(&mut iter, &arg)?,
                "--known-hosts-file" => {
                    config.known_hosts_file = Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "--signer-host" => config.signer_host = next_value(&mut iter, &arg)?,
                "--client-host" => config.client_host = next_value(&mut iter, &arg)?,
                "--signer-node-id" => config.signer_node_id = next_value(&mut iter, &arg)?,
                "--client-node-id" => config.client_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--zone-name" => config.zone_name = next_value(&mut iter, &arg)?,
                "--dns-interface" => config.dns_interface = next_value(&mut iter, &arg)?,
                "--dns-bind-addr" => config.dns_bind_addr = next_value(&mut iter, &arg)?,
                "--managed-peer" => {
                    let value = next_value(&mut iter, &arg)?;
                    config.managed_peers.push(parse_managed_peer_spec(&value)?);
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.is_empty() {
            return Err(
                "usage: live_linux_managed_dns_test --ssh-identity-file <path> [options]"
                    .to_owned(),
            );
        }
        Ok(config)
    }

    fn managed_fqdn(&self) -> String {
        format!("{MANAGED_LABEL}.{}", self.zone_name)
    }

    fn managed_alias_fqdn(&self) -> String {
        format!("{MANAGED_ALIAS}.{}", self.zone_name)
    }

    fn dns_server(&self) -> String {
        self.dns_bind_addr.split_once(':').map_or_else(
            || self.dns_bind_addr.clone(),
            |(server, _)| server.to_owned(),
        )
    }

    fn dns_port(&self) -> String {
        self.dns_bind_addr
            .split_once(':')
            .map_or_else(|| "53535".to_owned(), |(_, port)| port.to_owned())
    }
}

fn validate_targets(config: &Config) -> Result<(), String> {
    for (label, value) in [
        ("signer-host", config.signer_host.as_str()),
        ("client-host", config.client_host.as_str()),
        ("signer-node-id", config.signer_node_id.as_str()),
        ("client-node-id", config.client_node_id.as_str()),
        ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ("zone-name", config.zone_name.as_str()),
        ("dns-interface", config.dns_interface.as_str()),
        ("dns-bind-addr", config.dns_bind_addr.as_str()),
    ] {
        ensure_safe_token(label, value)?;
    }
    let mut seen_node_ids = HashSet::new();
    let mut seen_hosts = HashSet::new();
    for (label, value) in [
        ("signer-node-id", config.signer_node_id.as_str()),
        ("client-node-id", config.client_node_id.as_str()),
    ] {
        if !seen_node_ids.insert(value.to_owned()) {
            return Err(format!("{label} is duplicated: {value}"));
        }
    }
    for (label, value) in [
        ("signer-host", config.signer_host.as_str()),
        ("client-host", config.client_host.as_str()),
    ] {
        if !seen_hosts.insert(value.to_owned()) {
            return Err(format!("{label} is duplicated: {value}"));
        }
    }
    for peer in &config.managed_peers {
        ensure_safe_token("--managed-peer node-id", peer.node_id.as_str())?;
        ensure_safe_token("--managed-peer host", peer.host.as_str())?;
        if !seen_node_ids.insert(peer.node_id.clone()) {
            return Err(format!(
                "--managed-peer node-id duplicates an existing node id: {}",
                peer.node_id
            ));
        }
        if !seen_hosts.insert(peer.host.clone()) {
            return Err(format!(
                "--managed-peer host duplicates an existing host: {}",
                peer.host
            ));
        }
    }
    let _ = config
        .dns_bind_addr
        .split_once(':')
        .ok_or_else(|| "dns-bind-addr must be <ip:port>".to_owned())?
        .1
        .parse::<u16>()
        .map_err(|err| format!("invalid dns-bind-addr port: {err}"))?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DnsBundleTiming {
    generated_at: Option<u64>,
    nonce: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct DnsIssueContext<'a> {
    ctx: &'a LiveLabContext,
    signer_host: &'a str,
    passphrase_file: &'a str,
    zone_name: &'a str,
    nodes_spec: &'a str,
    allow_spec: &'a str,
    issue_dir: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct DnsBundleSpec<'a> {
    subject_node_id: &'a str,
    records_manifest_remote: &'a str,
    output_name: &'a str,
    timing: DnsBundleTiming,
}

#[derive(Debug, Clone, Copy)]
struct DnsBundleCaptureSpec<'a> {
    bundle: DnsBundleSpec<'a>,
    bundle_local: &'a Path,
}

#[derive(Debug, Clone, Copy)]
struct ManagedDnsValidationContext<'a> {
    logger: &'a Logger,
    root_dir: &'a Path,
    config: &'a Config,
    workspace: &'a Path,
    host_by_node: &'a HashMap<String, String>,
    platform_by_node: &'a HashMap<String, live_lab_support::LiveLabPlatform>,
    verifier_local: &'a Path,
    dns_issue: DnsIssueContext<'a>,
}

#[derive(Debug, Clone, Copy)]
struct InvalidBundleCaseSpec<'a> {
    bundle_local: &'a Path,
    clear_watermark: bool,
    case_label: &'a str,
    expected_reason_fragments: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
struct RestoreValidBundleSpec<'a> {
    valid_bundle_local: &'a Path,
    output_name: &'a str,
}

fn issue_dns_bundle(issue: DnsIssueContext<'_>, bundle: DnsBundleSpec<'_>) -> Result<(), String> {
    let output_path = format!("{}/{}", issue.issue_dir, bundle.output_name);
    let verifier_key_output = format!("{}/rn-dns-zone.pub", issue.issue_dir);
    let generated_at_string = bundle.timing.generated_at.map(|value| value.to_string());
    let nonce_string = bundle.timing.nonce.map(|value| value.to_string());
    let mut args = vec![
        "rustynet",
        "dns",
        "zone",
        "issue",
        "--signing-secret",
        "/etc/rustynet/membership.owner.key",
        "--signing-secret-passphrase-file",
        issue.passphrase_file,
        "--subject-node-id",
        bundle.subject_node_id,
        "--nodes",
        issue.nodes_spec,
        "--allow",
        issue.allow_spec,
        "--records-manifest",
        bundle.records_manifest_remote,
        "--output",
        output_path.as_str(),
        "--verifier-key-output",
        verifier_key_output.as_str(),
        "--zone-name",
        issue.zone_name,
        "--ttl-secs",
        "300",
    ];
    if bundle.timing.generated_at.is_some() {
        args.push("--generated-at");
        if let Some(generated_at_string) = generated_at_string.as_ref() {
            args.push(generated_at_string.as_str());
        }
    }
    if bundle.timing.nonce.is_some() {
        args.push("--nonce");
        if let Some(nonce_string) = nonce_string.as_ref() {
            args.push(nonce_string.as_str());
        }
    }
    issue.ctx.run_root(issue.signer_host, &args)?;
    Ok(())
}

fn issue_and_capture_valid_client_bundle(
    issue: DnsIssueContext<'_>,
    capture: DnsBundleCaptureSpec<'_>,
) -> Result<(), String> {
    issue_dns_bundle(issue, capture.bundle)?;
    capture_remote_text(
        issue.ctx,
        issue.signer_host,
        &format!("{}/{}", issue.issue_dir, capture.bundle.output_name),
        capture.bundle_local,
    )?;
    Ok(())
}

fn install_dns_bundle(
    ctx: &LiveLabContext,
    client_host: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    install_dns_bundle_with_options(ctx, client_host, verifier_local, bundle_local, true)
}

fn install_dns_bundle_with_options(
    ctx: &LiveLabContext,
    client_host: &str,
    verifier_local: &Path,
    bundle_local: &Path,
    clear_watermark: bool,
) -> Result<(), String> {
    retry_remote_step(
        &format!("install managed DNS bundle on {client_host}"),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            ctx.scp_to(verifier_local, client_host, "/tmp/rn-dns-zone.pub")?;
            ctx.scp_to(bundle_local, client_host, "/tmp/rn-dns-zone.bundle")?;
            ctx.run_root(
                client_host,
                &[
                    "install",
                    "-d",
                    "-m",
                    "0750",
                    "-o",
                    "rustynetd",
                    "-g",
                    "root",
                    "/etc/rustynet",
                ],
            )?;
            ctx.run_root(
                client_host,
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
            )?;
            ctx.run_root(
                client_host,
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
            )?;
            ctx.run_root(
                client_host,
                if clear_watermark {
                    &[
                        "rm",
                        "-f",
                        "/var/lib/rustynet/rustynetd.dns-zone.watermark",
                        "/tmp/rn-dns-zone.pub",
                        "/tmp/rn-dns-zone.bundle",
                    ]
                } else {
                    &[
                        "rm",
                        "-f",
                        "/tmp/rn-dns-zone.pub",
                        "/tmp/rn-dns-zone.bundle",
                    ]
                },
            )?;
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn refresh_traversal_bundles(
    ctx: &LiveLabContext,
    config: &Config,
    logger: &Logger,
    workspace: &Path,
    host_by_node: &HashMap<String, String>,
    platform_by_node: &HashMap<String, live_lab_support::LiveLabPlatform>,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<(), String> {
    retry_remote_step(
        &format!("refresh traversal bundles from {}", config.signer_host),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            let traversal_env = workspace.join("rn_issue_dns_traversal.env");
            write_env_file(
                &traversal_env,
                &[("NODES_SPEC", nodes_spec), ("ALLOW_SPEC", allow_spec)],
            )?;
            let remote_env_path = TRAVERSAL_ENV_REMOTE;
            ctx.scp_to(&traversal_env, &config.signer_host, remote_env_path)?;
            ctx.run_root(
                &config.signer_host,
                &[
                    "rustynet",
                    "ops",
                    "e2e-issue-traversal-bundles-from-env",
                    "--env-file",
                    remote_env_path,
                ],
            )?;
            ctx.run_root_allow_failure(&config.signer_host, &["rm", "-f", remote_env_path])?;

            let traversal_pub_local = workspace.join("traversal.pub");
            capture_remote_text(
                ctx,
                &config.signer_host,
                TRAVERSAL_PUB_REMOTE,
                &traversal_pub_local,
            )?;
            for (node_id, host) in sorted_node_host_pairs(host_by_node) {
                let node_platform = platform_by_node.get(&node_id).copied().ok_or_else(|| {
                    format!("missing platform mapping for traversal node {node_id}")
                })?;
                // install_traversal_bundle uses Linux paths and `-o root -g
                // rustynetd` ownership absent on macOS/Windows. Those peers got
                // valid signed traversal bundles during setup distribution and
                // the 86400s lab max-age keeps them fresh for the whole run.
                // Only the Linux client's resolution is asserted, so skip the
                // re-push to non-Linux peers.
                if node_platform != live_lab_support::LiveLabPlatform::Linux {
                    logger.line(format!(
                        "[managed-dns] skip bundle re-push for non-linux peer {node_id} ({platform}); setup-distributed bundles stay fresh under the 86400s lab window",
                        platform = node_platform.as_str()
                    ))?;
                    continue;
                }
                let traversal_remote = traversal_bundle_remote_path(node_id.as_str());
                let traversal_local = workspace.join(format!("traversal-{node_id}.bundle"));
                capture_remote_text(
                    ctx,
                    &config.signer_host,
                    traversal_remote.as_str(),
                    &traversal_local,
                )?;
                install_traversal_bundle(ctx, &host, &traversal_pub_local, &traversal_local)?;
            }
            ctx.run_root_allow_failure(&config.signer_host, &["rm", "-rf", TRAVERSAL_ISSUE_DIR])?;
            Ok(())
        },
    )
}

fn sorted_node_host_pairs(host_by_node: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut entries = host_by_node
        .iter()
        .map(|(node_id, host)| (node_id.clone(), host.clone()))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    entries
}

fn managed_dns_distribution_targets(
    host_by_node: &HashMap<String, String>,
    client_host: &str,
) -> Vec<(String, String)> {
    sorted_node_host_pairs(host_by_node)
        .into_iter()
        .filter(|(_, host)| host != client_host)
        .collect()
}

fn traversal_bundle_remote_path(node_id: &str) -> String {
    format!("/run/rustynet/traversal-issue/rn-traversal-{node_id}.traversal")
}

fn install_traversal_bundle(
    ctx: &LiveLabContext,
    host: &str,
    traversal_pub_local: &Path,
    traversal_bundle_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(traversal_pub_local, host, "/tmp/rn-traversal.pub")?;
    ctx.scp_to(traversal_bundle_local, host, "/tmp/rn-traversal.bundle")?;
    ctx.run_root(
        host,
        &[
            "install",
            "-d",
            "-m",
            "0750",
            "-o",
            "rustynetd",
            "-g",
            "root",
            "/etc/rustynet",
        ],
    )?;
    ctx.run_root(
        host,
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
    )?;
    ctx.run_root(
        host,
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
    )?;
    ctx.run_root(
        host,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.traversal.watermark",
            "/tmp/rn-traversal.pub",
            "/tmp/rn-traversal.bundle",
        ],
    )?;
    Ok(())
}

/// Start `rustynetd.service` resiliently against the systemd start-limit.
///
/// The managed-DNS validator deliberately makes the client daemon reject
/// adversarial bundles; a fatal traversal-preflight rejection makes the daemon
/// exit non-zero, so the unit's own `Restart=on-failure` issues auto-restarts.
/// Combined with the validator's explicit `systemctl start` calls these can
/// exceed `StartLimitBurst` (5 in 60s) and latch the unit in `start-limit-hit`,
/// after which every `systemctl start` returns non-zero and a plain retry loop
/// can never recover. Clear the latch with `reset-failed` before EACH start
/// attempt so a transient start-limit never aborts the stage.
///
/// This only hardens the harness's restart discipline: it does not modify the
/// production unit, its StartLimit settings, or the daemon's correct
/// fail-closed rejection of invalid bundles (which is exactly what this stage
/// asserts).
fn start_rustynetd_with_reset(
    ctx: &LiveLabContext,
    client_host: &str,
    attempts: u32,
    sleep_secs: u64,
) -> Result<(), String> {
    let mut last_err = None;
    for attempt in 1..=attempts {
        // Clear any start-limit latch accumulated by the unit's own
        // Restart=on-failure before trying to start again.
        let _ = ctx.run_root_allow_failure(
            client_host,
            &["systemctl", "reset-failed", "rustynetd.service"],
        );
        match ctx.run_root(client_host, &["systemctl", "start", "rustynetd.service"]) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    sleep(std::time::Duration::from_secs(sleep_secs));
                }
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| "start rustynetd.service retry exhausted after reset-failed".to_owned()))
}

fn restart_managed_dns_stack(ctx: &LiveLabContext, client_host: &str) -> Result<(), String> {
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "stop",
            "rustynetd-managed-dns.service",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-managed-dns.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "start", "rustynetd-privileged-helper.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &[
            "systemctl",
            "is-active",
            "rustynetd-privileged-helper.service",
        ],
        15,
        2,
    )?;
    start_rustynetd_with_reset(ctx, client_host, 5, 2)?;
    ctx.wait_for_daemon_socket(client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    ctx.retry_root(
        client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "state",
            "refresh",
        ],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "restart", "rustynetd-managed-dns.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "is-active", "rustynetd-managed-dns.service"],
        15,
        2,
    )?;
    wait_for_dns_inspect_state(ctx, client_host, Some("valid"), 20, 2)?;
    Ok(())
}

fn refresh_signer_trust_evidence(ctx: &LiveLabContext, signer_host: &str) -> Result<(), String> {
    ctx.retry_root(
        signer_host,
        &["rustynet", "ops", "refresh-signed-trust"],
        5,
        2,
    )
}

fn build_authorized_allow_spec(
    assignment_scopes: &HashMap<String, AssignmentAuthorityScope>,
    host_by_node: &HashMap<String, String>,
) -> Result<String, String> {
    let mut pairs = Vec::new();
    for node_id in sorted_node_host_pairs(host_by_node)
        .into_iter()
        .map(|(node_id, _)| node_id)
    {
        let scope = assignment_scopes
            .get(&node_id)
            .ok_or_else(|| format!("missing assignment authority scope for {node_id}"))?;
        for peer_node_id in &scope.peer_node_ids {
            if !host_by_node.contains_key(peer_node_id.as_str()) {
                return Err(format!(
                    "assignment bundle for {node_id} references unmanaged peer {peer_node_id}"
                ));
            }
            pairs.push(format!("{node_id}|{peer_node_id}"));
        }
    }
    pairs.sort();
    pairs.dedup();
    if pairs.is_empty() {
        return Err(
            "managed DNS traversal issuance requires at least one authorized allow pair".to_owned(),
        );
    }
    Ok(pairs.join(";"))
}

fn capture_assignment_authority_scopes(
    ctx: &LiveLabContext,
    host_by_node: &HashMap<String, String>,
    platform_by_node: &HashMap<String, live_lab_support::LiveLabPlatform>,
) -> Result<HashMap<String, AssignmentAuthorityScope>, String> {
    let mut scopes = HashMap::new();
    for (node_id, host) in sorted_node_host_pairs(host_by_node) {
        let platform = platform_by_node
            .get(&node_id)
            .copied()
            .ok_or_else(|| format!("missing platform mapping for node {node_id}"))?;
        // Locate the assignment bundle per-OS; the cat stays argv-only.
        let assignment_bundle =
            ctx.capture_root(&host, &["cat", assignment_bundle_path(platform)])?;
        let scope = parse_assignment_authority_scope(&assignment_bundle)?;
        if scope.node_id != node_id {
            return Err(format!(
                "assignment bundle subject {subject} does not match expected node {expected} on {host}",
                subject = scope.node_id,
                expected = node_id,
            ));
        }
        scopes.insert(node_id, scope);
    }
    Ok(scopes)
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

fn managed_dns_base_records(
    signer_node_id: &str,
    client_node_id: &str,
) -> Vec<ManagedDnsRecordTemplate> {
    vec![
        ManagedDnsRecordTemplate {
            label: MANAGED_LABEL.to_owned(),
            target_node_id: signer_node_id.to_owned(),
            ttl_secs: 300,
            aliases: vec![MANAGED_ALIAS.to_owned()],
        },
        ManagedDnsRecordTemplate {
            label: "client".to_owned(),
            target_node_id: client_node_id.to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
    ]
}

fn managed_dns_replay_records(
    records: &[ManagedDnsRecordTemplate],
    signer_node_id: &str,
) -> Result<Vec<ManagedDnsRecordTemplate>, String> {
    let mut replay_records = records.to_vec();
    let signer_record = replay_records
        .iter_mut()
        .find(|record| record.target_node_id == signer_node_id)
        .ok_or_else(|| {
            format!("managed DNS replay probe could not find signer record for {signer_node_id}")
        })?;
    if signer_record
        .aliases
        .iter()
        .any(|alias| alias == REPLAY_PROBE_ALIAS)
    {
        return Err(format!(
            "managed DNS replay probe alias already present: {REPLAY_PROBE_ALIAS}"
        ));
    }
    signer_record.aliases.push(REPLAY_PROBE_ALIAS.to_owned());
    Ok(replay_records)
}

fn managed_dns_records_manifest_for_scope(
    records: &[ManagedDnsRecordTemplate],
    scope: &AssignmentAuthorityScope,
) -> Result<String, String> {
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
        return Err(format!(
            "managed DNS scope for {} produced no policy-authorized records",
            scope.node_id
        ));
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

fn parse_assignment_authority_scope(bundle: &str) -> Result<AssignmentAuthorityScope, String> {
    let mut node_id = None;
    let mut peer_node_ids = Vec::new();
    for line in bundle.lines() {
        if let Some(value) = line.strip_prefix("node_id=") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err("assignment bundle node_id must not be empty".to_owned());
            }
            node_id = Some(trimmed.to_owned());
            continue;
        }
        if let Some((prefix, value)) = line.split_once('=')
            && prefix.starts_with("peer.")
            && prefix.ends_with(".node_id")
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "assignment bundle peer id must not be empty: {prefix}"
                ));
            }
            peer_node_ids.push(trimmed.to_owned());
        }
    }
    peer_node_ids.sort();
    peer_node_ids.dedup();
    Ok(AssignmentAuthorityScope {
        node_id: node_id.ok_or_else(|| "assignment bundle is missing node_id".to_owned())?,
        peer_node_ids,
    })
}

fn rewrite_bundle_line_value(
    bundle: &str,
    field_key: &str,
    new_value: &str,
) -> Result<String, String> {
    let prefix = format!("{field_key}=");
    let mut updated = Vec::new();
    let mut replaced = false;
    for line in bundle.lines() {
        if !replaced && line.starts_with(prefix.as_str()) {
            updated.push(format!("{prefix}{new_value}"));
            replaced = true;
        } else {
            updated.push(line.to_owned());
        }
    }
    if !replaced {
        return Err(format!(
            "dns bundle field not found for rewrite: {field_key}"
        ));
    }
    Ok(updated.join("\n") + "\n")
}

fn rewrite_bundle_signature(bundle: &str, fill: &str) -> Result<String, String> {
    let mut updated = Vec::new();
    let mut replaced = false;
    for line in bundle.lines() {
        if !replaced && line.starts_with("signature=") {
            let hex = line.trim_start_matches("signature=");
            if hex.is_empty() {
                return Err("dns bundle signature line must not be empty".to_owned());
            }
            updated.push(format!("signature={}", fill.repeat(hex.len())));
            replaced = true;
        } else {
            updated.push(line.to_owned());
        }
    }
    if !replaced {
        return Err("dns bundle is missing signature line".to_owned());
    }
    Ok(updated.join("\n") + "\n")
}

#[derive(Debug, Clone)]
struct InvalidBundleCaseResult {
    passed: bool,
}

#[derive(Debug, Clone)]
struct RemoteDnsQueryCapture {
    payload: String,
    command_failed: bool,
    failure_reason: String,
}

fn exercise_invalid_bundle_case(
    validation: ManagedDnsValidationContext<'_>,
    case: InvalidBundleCaseSpec<'_>,
) -> Result<InvalidBundleCaseResult, String> {
    validation.logger.line(
        format!(
            "[managed-dns] installing {case_label} managed DNS bundle on {}",
            validation.config.client_host,
            case_label = case.case_label,
        )
        .as_str(),
    )?;
    install_dns_bundle_with_options(
        validation.dns_issue.ctx,
        &validation.config.client_host,
        validation.verifier_local,
        case.bundle_local,
        case.clear_watermark,
    )?;
    refresh_traversal_bundles(
        validation.dns_issue.ctx,
        validation.config,
        validation.logger,
        validation.workspace,
        validation.host_by_node,
        validation.platform_by_node,
        validation.dns_issue.nodes_spec,
        validation.dns_issue.allow_spec,
    )?;
    let dns_inspect = restart_managed_dns_stack_allow_invalid_dns(
        validation.dns_issue.ctx,
        &validation.config.client_host,
    )?;
    // Daemon hosting-state + recent daemon log. Per-OS:
    //   Linux   → `systemctl is-active rustynetd.service` + `journalctl`
    //   macOS   → daemon hosting-state via the managed-resolver service probe
    //             + `log show --predicate 'process == "rustynetd"'`
    //   Windows → SCM service state + `Get-WinEvent` daemon log tail
    // The journal is only a *fallback* signal for the fail-closed assertion:
    // `managed_dns_invalid_state_observed` first honours the OS-independent
    // `dns inspect: state=invalid` readback, so a missing/absent per-OS log
    // tail can never fake a pass.
    let rustynetd_state = capture_hosting_daemon_state(
        validation.dns_issue.ctx,
        &validation.config.client_host,
        validation.config,
    )?;
    let rustynetd_journal = capture_daemon_log_tail(
        validation.dns_issue.ctx,
        &validation.config.client_host,
        validation.config,
    )?;
    let direct_query = remote_dns_query_capture_allow_failure(
        validation.dns_issue.ctx,
        &validation.config.client_host,
        validation.config,
        &validation.config.managed_fqdn(),
    )?;
    let direct_query_log = if direct_query.payload.trim().is_empty() && direct_query.command_failed
    {
        format!(
            "{{\"error\":\"query command failed closed\",\"failure_reason\":{}}}",
            serde_json::to_string(&direct_query.failure_reason)
                .map_err(|err| format!("serialize DNS query failure reason failed: {err}"))?
        )
    } else {
        direct_query.payload.clone()
    };

    validation.logger.block(
        format!(
            "[managed-dns] {case_label} dns inspect",
            case_label = case.case_label
        )
        .as_str(),
        &dns_inspect,
    )?;
    validation.logger.block(
        format!(
            "[managed-dns] {case_label} rustynetd state",
            case_label = case.case_label
        )
        .as_str(),
        &rustynetd_state,
    )?;
    validation.logger.block(
        format!(
            "[managed-dns] {case_label} rustynetd journal",
            case_label = case.case_label
        )
        .as_str(),
        &rustynetd_journal,
    )?;
    validation.logger.block(
        format!(
            "[managed-dns] {case_label} loopback DNS query",
            case_label = case.case_label
        )
        .as_str(),
        &direct_query_log,
    )?;

    let passed = managed_dns_invalid_state_observed(
        dns_inspect.as_str(),
        rustynetd_journal.as_str(),
        case.expected_reason_fragments,
    ) && dns_query_failed_closed(
        validation.root_dir,
        direct_query.payload.as_str(),
        direct_query.command_failed,
    )?;

    Ok(InvalidBundleCaseResult { passed })
}

fn restart_managed_dns_stack_allow_invalid_dns(
    ctx: &LiveLabContext,
    client_host: &str,
) -> Result<String, String> {
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "stop",
            "rustynetd-managed-dns.service",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-managed-dns.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "start", "rustynetd-privileged-helper.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &[
            "systemctl",
            "is-active",
            "rustynetd-privileged-helper.service",
        ],
        15,
        2,
    )?;
    ctx.run_root_allow_failure(client_host, &["systemctl", "start", "rustynetd.service"])?;
    ctx.run_root_allow_failure(
        client_host,
        &["systemctl", "restart", "rustynetd-managed-dns.service"],
    )?;
    ctx.wait_for_daemon_socket(client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    wait_for_dns_inspect_state(ctx, client_host, None, 20, 2)
}

fn restore_valid_bundle_after_invalid_case(
    validation: ManagedDnsValidationContext<'_>,
    restore: RestoreValidBundleSpec<'_>,
) -> Result<(), String> {
    retry_remote_step(
        &format!(
            "restore valid managed DNS bundle on {}",
            validation.config.client_host
        ),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            issue_and_capture_valid_client_bundle(
                validation.dns_issue,
                DnsBundleCaptureSpec {
                    bundle: DnsBundleSpec {
                        subject_node_id: &validation.config.client_node_id,
                        records_manifest_remote: DNS_RECORDS_REMOTE,
                        output_name: restore.output_name,
                        timing: DnsBundleTiming {
                            generated_at: None,
                            nonce: None,
                        },
                    },
                    bundle_local: restore.valid_bundle_local,
                },
            )?;
            install_dns_bundle(
                validation.dns_issue.ctx,
                &validation.config.client_host,
                validation.verifier_local,
                restore.valid_bundle_local,
            )?;
            refresh_traversal_bundles(
                validation.dns_issue.ctx,
                validation.config,
                validation.logger,
                validation.workspace,
                validation.host_by_node,
                validation.platform_by_node,
                validation.dns_issue.nodes_spec,
                validation.dns_issue.allow_spec,
            )?;
            restart_managed_dns_stack(validation.dns_issue.ctx, &validation.config.client_host)
        },
    )
}

fn retry_remote_step<T, F>(
    label: &str,
    attempts: u32,
    sleep_secs: u64,
    mut operation: F,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, String>,
{
    let mut last_err = None;
    for attempt in 1..=attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    sleep(std::time::Duration::from_secs(sleep_secs));
                }
            }
        }
    }
    Err(format!(
        "{label} failed after {attempts} attempts: {}",
        last_err.unwrap_or_else(|| "retry exhausted".to_owned())
    ))
}

fn wait_for_dns_inspect_state(
    ctx: &LiveLabContext,
    client_host: &str,
    expected_state: Option<&str>,
    attempts: u32,
    sleep_secs: u64,
) -> Result<String, String> {
    let mut last_output = None;
    for attempt in 1..=attempts {
        let output = ctx.capture_root_allow_failure_with_retry(
            client_host,
            &[
                "env",
                "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
                "rustynet",
                "dns",
                "inspect",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        )?;
        if dns_inspect_readback_ready(output.as_str())
            && dns_inspect_matches_expected_state(output.as_str(), expected_state)
        {
            return Ok(output);
        }
        last_output = Some(output);
        if attempt < attempts {
            sleep(std::time::Duration::from_secs(sleep_secs));
        }
    }
    Err(format!(
        "managed DNS inspect did not converge on {client_host}: {}",
        last_output
            .map(|output| output.trim().to_owned())
            .filter(|output| !output.is_empty())
            .unwrap_or_else(|| "empty output".to_owned())
    ))
}

fn dns_inspect_readback_ready(output: &str) -> bool {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return false;
    }
    let normalized = normalize_reason_text(trimmed);
    !normalized.contains("daemon unreachable")
        && !normalized.contains("inspect daemon socket failed")
}

fn dns_inspect_matches_expected_state(output: &str, expected_state: Option<&str>) -> bool {
    match expected_state {
        Some(state) => output.contains(&format!("dns inspect: state={state}")),
        None => output.contains("dns inspect: state="),
    }
}

fn managed_dns_invalid_state_observed(
    dns_inspect: &str,
    rustynetd_journal: &str,
    expected_reason_fragments: &[&str],
) -> bool {
    if dns_inspect.contains("dns inspect: state=invalid")
        && contains_all_reason_fragments(dns_inspect, expected_reason_fragments)
    {
        return true;
    }
    let journal_lower = rustynetd_journal.to_ascii_lowercase();
    let journal_has_preflight_marker = journal_lower.contains("dns zone preflight failed")
        || journal_lower.contains("dns zone preflight skipped invalid managed dns bundle");
    journal_has_preflight_marker
        && contains_all_reason_fragments(rustynetd_journal, expected_reason_fragments)
}

fn contains_all_reason_fragments(haystack: &str, expected_reason_fragments: &[&str]) -> bool {
    let normalized_haystack = normalize_reason_text(haystack);
    expected_reason_fragments.iter().all(|fragment| {
        let normalized_fragment = normalize_reason_text(fragment);
        normalized_haystack.contains(normalized_fragment.as_str())
    })
}

fn normalize_reason_text(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', " ")
}

fn dns_query_failed_closed(
    root_dir: &Path,
    direct_query: &str,
    command_failed: bool,
) -> Result<bool, String> {
    if direct_query.trim().is_empty() {
        return Ok(command_failed);
    }
    let rcode = json_field(root_dir, direct_query, "rcode")?;
    let error = json_field(root_dir, direct_query, "error")?;
    Ok(rcode != "0" || !error.trim().is_empty())
}

fn capture_remote_text(
    ctx: &LiveLabContext,
    host: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let body = ctx.capture_root(host, &["cat", remote_path])?;
    write_secure_text(local_path, &body)
}

fn run_cargo_ops_capture(
    root_dir: &Path,
    subcommand: &str,
    args: &[&str],
) -> Result<String, String> {
    let output = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            subcommand,
        ])
        .args(args)
        .output()
        .map_err(|err| format!("failed to run cargo ops {subcommand}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo ops {subcommand} failed with status {}: {}",
            live_lab_support::status_code(output.status),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn remote_dns_query_capture(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
    qname: &str,
) -> Result<String, String> {
    ctx.capture_root(
        host,
        &[
            "rustynet",
            "ops",
            "e2e-dns-query",
            "--server",
            &config.dns_server(),
            "--port",
            &config.dns_port(),
            "--qname",
            qname,
            "--timeout-ms",
            "3000",
        ],
    )
}

fn remote_dns_query_capture_allow_failure(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
    qname: &str,
) -> Result<RemoteDnsQueryCapture, String> {
    let output = ctx.run_root_allow_failure_with_retry(
        host,
        &[
            "rustynet",
            "ops",
            "e2e-dns-query",
            "--server",
            &config.dns_server(),
            "--port",
            &config.dns_port(),
            "--qname",
            qname,
            "--timeout-ms",
            "3000",
        ],
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
    )?;
    Ok(RemoteDnsQueryCapture {
        payload: String::from_utf8_lossy(&output.stdout).into_owned(),
        command_failed: !output.status.success(),
        failure_reason: render_remote_output(&output),
    })
}

// ─── Per-OS resolver-stack inspection (Wave 2 W2-D cross-OS port) ──────────
//
// These captures replace three Linux-only command sites with runtime
// `match platform` branches. Each capture is paired with a pure parser
// (below) that is unit-tested against realistic per-OS output so the
// inference about the command shape is verifiable on this Linux host.

/// Capture the split-DNS / resolver-configuration status from the client.
///
/// Per-OS command choice + WHY:
///   * Linux   → `resolvectl status <iface>`: systemd-resolved is the
///     canonical Linux resolver and `status <iface>` shows the per-link DNS
///     server + the `~<zone>` routing domain that proves split-DNS routing.
///     (Byte-identical to the pre-Wave-2 Linux command.)
///   * macOS   → `scutil --dns`: the System Configuration framework's
///     resolver dump lists every configured resolver with its `nameserver[n]`
///     and `domain`/`search domain` — the macOS equivalent of resolvectl's
///     per-link view. `dscacheutil` cannot show resolver *configuration*, so
///     `scutil --dns` is the correct inspection verb.
///   * Windows → `Get-DnsClientServerAddress`: the DnsClient cmdlet prints
///     each interface's configured DNS server addresses; combined with the
///     loopback bind address this proves the host points at the managed
///     resolver. (NRPT split-zone routing is a deeper check the daemon owns;
///     the configured-server view is the directly-observable split-DNS proof.)
fn capture_resolver_config_status(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
) -> Result<String, String> {
    match config.platform {
        LiveLabPlatform::Linux => {
            ctx.capture_root_allow_failure(host, &["resolvectl", "status", &config.dns_interface])
        }
        LiveLabPlatform::MacOs => {
            // `scutil --dns` never fails for missing config; it just prints an
            // empty resolver list, which the parser treats as "not configured"
            // (fail-closed). argv-only; no untrusted interpolation.
            ctx.capture_root_allow_failure(host, &["scutil", "--dns"])
        }
        LiveLabPlatform::Windows => {
            // Emit the configured DNS servers as `<ifAlias>=<server>` rows so
            // the parser sees the loopback resolver without depending on the
            // default Format-Table layout. The script body is a hardcoded
            // constant — no runtime data crosses the shell boundary.
            ctx.capture_root_allow_failure(
                host,
                &[
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientServerAddress | ForEach-Object { foreach ($s in $_.ServerAddresses) { \"$($_.InterfaceAlias)=$s\" } }",
                ],
            )
        }
    }
}

/// Flush the OS resolver cache before the system-resolver answer probe so a
/// previously-cached negative answer cannot mask a freshly-installed bundle.
/// Per-OS verb: Linux `resolvectl flush-caches`, macOS
/// `dscacheutil -flushcache`, Windows `Clear-DnsClientCache`. Failures are
/// tolerated (the cache may already be empty); this is a hygiene step, not an
/// assertion.
fn flush_os_resolver_cache(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
) -> Result<(), String> {
    let _ = match config.platform {
        LiveLabPlatform::Linux => {
            ctx.run_root_allow_failure(host, &["resolvectl", "flush-caches"])?
        }
        LiveLabPlatform::MacOs => {
            ctx.run_root_allow_failure(host, &["dscacheutil", "-flushcache"])?
        }
        LiveLabPlatform::Windows => ctx.run_root_allow_failure(
            host,
            &[
                "powershell",
                "-NoProfile",
                "-Command",
                "Clear-DnsClientCache",
            ],
        )?,
    };
    Ok(())
}

/// Capture the OS system-resolver's answer for the managed FQDN.
///
/// Per-OS command choice + WHY:
///   * Linux   → `resolvectl query --legend=no <fqdn>`: routes through
///     systemd-resolved exactly as a normal application would, proving the
///     split-DNS route reaches the managed resolver. (Byte-identical to the
///     pre-Wave-2 Linux command, including the `timeout 15` wrapper.)
///   * macOS   → `dig @<server> -p <port> <fqdn> +short`: macOS has no
///     `resolvectl`. `dig` aimed at the managed loopback resolver
///     (127.0.0.1:53535) is the system `dig`'s view of the same resolver,
///     and `dscacheutil -q host` is captured alongside as the directory-
///     service cache corroboration. (`dscacheutil` alone cannot target a
///     custom port, so it cannot stand in for the managed-resolver probe.)
///   * Windows → `Resolve-DnsName -Server 127.0.0.1 -Name <fqdn>` plus
///     `nslookup <fqdn> 127.0.0.1`: `Resolve-DnsName` is the modern
///     PowerShell resolver cmdlet and `nslookup` the classic fallback; both
///     are pointed at the managed loopback resolver. There is no
///     `Get-DnsClientServerAddress` *answer* — that cmdlet only reports
///     configuration — so it is used for the split-DNS config check, not the
///     answer probe.
fn capture_os_resolver_answer(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
    fqdn: &str,
) -> Result<String, String> {
    match config.platform {
        LiveLabPlatform::Linux => {
            let resolvectl_query_cmd = format!(
                "if command -v timeout >/dev/null 2>&1; then timeout 15 resolvectl query --legend=no {fqdn}; else resolvectl query --legend=no {fqdn}; fi",
                fqdn = shell_single_quote(fqdn)
            );
            ctx.capture_root_allow_failure(host, &["sh", "-lc", resolvectl_query_cmd.as_str()])
        }
        LiveLabPlatform::MacOs => {
            let server = config.dns_server();
            let port = config.dns_port();
            // `dig` short answer against the managed resolver, then the
            // directory-service cache view for the same name. argv-only.
            let dig_answer = ctx.capture_root_allow_failure(
                host,
                &["dig", &format!("@{server}"), "-p", &port, fqdn, "+short"],
            )?;
            let dscacheutil_answer = ctx.capture_root_allow_failure(
                host,
                &["dscacheutil", "-q", "host", "-a", "name", fqdn],
            )?;
            Ok(format!(
                "dig +short:\n{dig_answer}\ndscacheutil:\n{dscacheutil_answer}"
            ))
        }
        LiveLabPlatform::Windows => {
            let server = config.dns_server();
            // Resolve-DnsName against the managed resolver, IP addresses only,
            // plus an nslookup fallback. The script interpolates only the
            // already-`ensure_safe_token`-validated server + the const-derived
            // managed FQDN, so no untrusted value reaches the shell.
            let script = format!(
                "$ErrorActionPreference='SilentlyContinue'; (Resolve-DnsName -Server {server} -Name {fqdn} -Type A | Select-Object -ExpandProperty IPAddress); 'nslookup:'; (nslookup {fqdn} {server} 2>$null)"
            );
            ctx.capture_root_allow_failure(host, &["powershell", "-NoProfile", "-Command", &script])
        }
    }
}

/// Capture the hosting-state of the managed DNS resolver.
///
/// Per-OS command choice + WHY:
///   * Linux   → `systemctl is-active rustynetd-managed-dns.service`: the
///     managed resolver runs as a dedicated systemd unit. (Byte-identical to
///     the pre-Wave-2 Linux command.)
///   * macOS   → `launchctl print system/com.rustynet.daemon` reduced to a
///     state word: there is NO separate managed-DNS launchd job — the
///     resolver is hosted in the main daemon — so the live proof is that the
///     hosting daemon is loaded/running.
///   * Windows → `(Get-Service -Name RustyNet).Status`: same rationale — the
///     resolver is hosted in the main SCM service.
///
// REVIEW (daemon-side gap, flagged for the live run): macOS/Windows do NOT
// expose a standalone managed-DNS service the way Linux's
// `rustynetd-managed-dns.service` does. This capture confirms the *hosting*
// daemon is live, which is the strongest directly-observable proxy. If a
// future build splits the resolver into its own launchd/SCM job, swap the
// label here. A dead daemon fails this check closed (never a fake pass).
fn capture_managed_dns_service_state(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
) -> Result<String, String> {
    match config.platform {
        // No-retry to stay byte-identical with the pre-Wave-2 Linux call.
        LiveLabPlatform::Linux => ctx.capture_root_allow_failure(
            host,
            &["systemctl", "is-active", "rustynetd-managed-dns.service"],
        ),
        LiveLabPlatform::MacOs => ctx.capture_root_allow_failure(
            host,
            &[
                "sh",
                "-lc",
                "/bin/launchctl print system/com.rustynet.daemon 2>&1 || true",
            ],
        ),
        LiveLabPlatform::Windows => ctx.capture_root_allow_failure(
            host,
            &[
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Service -Name 'RustyNet' -ErrorAction SilentlyContinue).Status",
            ],
        ),
    }
}

/// Capture the hosting-daemon state for the fail-closed adversarial cases'
/// diagnostic log block. Per-OS:
///   * Linux   → `systemctl is-active rustynetd.service` (with retry, exactly
///     as the pre-Wave-2 invalid-case capture)
///   * macOS   → `launchctl print system/com.rustynet.daemon`
///   * Windows → `(Get-Service -Name RustyNet).Status`
///
/// This is diagnostic-only — it is logged but never feeds the pass/fail
/// decision (`managed_dns_invalid_state_observed` consumes `dns_inspect` and
/// the daemon log tail, not this state word).
fn capture_hosting_daemon_state(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
) -> Result<String, String> {
    match config.platform {
        LiveLabPlatform::Linux => ctx.capture_root_allow_failure_with_retry(
            host,
            &["systemctl", "is-active", "rustynetd.service"],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
        LiveLabPlatform::MacOs => ctx.capture_root_allow_failure_with_retry(
            host,
            &[
                "sh",
                "-lc",
                "/bin/launchctl print system/com.rustynet.daemon 2>&1 || true",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
        LiveLabPlatform::Windows => ctx.capture_root_allow_failure_with_retry(
            host,
            &[
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Service -Name 'RustyNet' -ErrorAction SilentlyContinue).Status",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
    }
}

/// Capture a recent tail of the daemon log (fallback signal for the
/// fail-closed adversarial cases). Per-OS:
///   * Linux   → `journalctl -u rustynetd.service -n 40 --no-pager`
///   * macOS   → `log show --last 5m --predicate 'process == "rustynetd"'`
///   * Windows → `Get-WinEvent` over the RustyNet provider (best-effort)
///
// REVIEW: the macOS `log show` predicate and the Windows event provider name
// are inferred from the daemon process name; the fail-closed assertion does
// NOT depend on this log tail (it primarily honours the OS-independent
// `dns inspect: state=invalid` readback), so an empty/unsupported log tail
// degrades to the portable path rather than failing the test spuriously or
// faking a pass.
fn capture_daemon_log_tail(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
) -> Result<String, String> {
    match config.platform {
        LiveLabPlatform::Linux => ctx.capture_root_allow_failure_with_retry(
            host,
            &[
                "journalctl",
                "-u",
                "rustynetd.service",
                "-n",
                "40",
                "--no-pager",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
        LiveLabPlatform::MacOs => ctx.capture_root_allow_failure_with_retry(
            host,
            &[
                "sh",
                "-lc",
                "log show --last 5m --predicate 'process == \"rustynetd\"' --style compact 2>/dev/null || true",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
        LiveLabPlatform::Windows => ctx.capture_root_allow_failure_with_retry(
            host,
            &[
                "powershell",
                "-NoProfile",
                "-Command",
                "try { Get-WinEvent -ProviderName 'RustyNet' -MaxEvents 40 -ErrorAction Stop | Format-List | Out-String -Width 32767 } catch { '' }",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        ),
    }
}

// ─── Pure per-OS parsers (unit-tested) ─────────────────────────────────────

/// True when the captured resolver-configuration output proves the managed
/// loopback resolver is the configured DNS path for the mesh zone.
///
///   * Linux: `resolvectl status` must show the managed bind address AND the
///     `~<zone>` routing domain (or the `DNS Domain: <zone>` form). This is
///     byte-identical to the pre-Wave-2 assertion.
///   * macOS: `scutil --dns` must list the managed loopback `nameserver` for
///     a resolver whose `domain`/`search domain` covers the mesh zone.
///   * Windows: `Get-DnsClientServerAddress` (rendered as `<ifAlias>=<server>`
///     rows) must list the managed loopback server.
fn resolver_config_advertises_managed_zone(
    platform: LiveLabPlatform,
    output: &str,
    dns_bind_addr: &str,
    dns_server: &str,
    zone_name: &str,
) -> bool {
    match platform {
        LiveLabPlatform::Linux => {
            output.contains(dns_bind_addr)
                && (output.contains(&format!("~{zone_name}"))
                    || output.contains(&format!("DNS Domain: {zone_name}")))
        }
        LiveLabPlatform::MacOs => {
            macos_scutil_advertises_managed_zone(output, dns_server, zone_name)
        }
        LiveLabPlatform::Windows => windows_dns_client_lists_loopback_server(output, dns_server),
    }
}

/// macOS `scutil --dns` parser. The dump groups resolvers in
/// `resolver #N { ... }` blocks, each carrying `nameserver[i] : <ip>` and
/// `domain : <suffix>` / `search domain[i] : <suffix>` lines. We accept the
/// config as advertising the managed zone when SOME resolver block lists the
/// managed loopback nameserver AND a resolver block scopes the mesh zone
/// (default resolvers, which have no domain, do not satisfy the zone scope —
/// that prevents a plain loopback forwarder from masquerading as split-DNS).
fn macos_scutil_advertises_managed_zone(output: &str, dns_server: &str, zone_name: &str) -> bool {
    let mut has_managed_nameserver = false;
    let mut has_zone_domain = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.starts_with("nameserver") && value == dns_server {
                has_managed_nameserver = true;
            }
            if (key == "domain" || key.starts_with("search domain")) && value == zone_name {
                has_zone_domain = true;
            }
        }
    }
    has_managed_nameserver && has_zone_domain
}

/// Windows configured-DNS-server parser. The capture emits
/// `<InterfaceAlias>=<ServerAddress>` rows. The managed posture requires at
/// least one interface configured with the managed loopback resolver.
fn windows_dns_client_lists_loopback_server(output: &str, dns_server: &str) -> bool {
    output.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(_, server)| server.trim() == dns_server)
    })
}

/// True when the OS system-resolver answer carries the expected A record.
///
///   * Linux: `resolvectl query` prints `<fqdn>: <ip>` — substring match on
///     the IP (byte-identical to the pre-Wave-2 assertion).
///   * macOS: the combined `dig +short` / `dscacheutil` capture must contain
///     the IP as a standalone token (not a substring of a larger address).
///   * Windows: the `Resolve-DnsName` / `nslookup` capture must contain the
///     IP as a standalone token.
fn os_resolver_answer_contains_ip(
    platform: LiveLabPlatform,
    output: &str,
    expected_ip: &str,
) -> bool {
    if expected_ip.is_empty() {
        return false;
    }
    match platform {
        // Preserve the exact pre-Wave-2 Linux behaviour: a plain substring
        // check against the resolvectl query output.
        LiveLabPlatform::Linux => output.contains(expected_ip),
        // macOS / Windows: require the IP as a whitespace/line-delimited token
        // so `100.64.0.10` cannot be satisfied by `100.64.0.100`.
        LiveLabPlatform::MacOs | LiveLabPlatform::Windows => {
            answer_contains_ip_token(output, expected_ip)
        }
    }
}

/// Token-exact IP match: the expected IP must appear bounded by line/word
/// boundaries (whitespace, line ends, or common delimiters) so a longer IP
/// that merely contains the expected one as a prefix/substring does not match.
fn answer_contains_ip_token(output: &str, expected_ip: &str) -> bool {
    output
        .split(|ch: char| {
            ch.is_whitespace()
                || matches!(ch, '\t' | ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'')
        })
        .any(|token| token == expected_ip)
}

/// True when the captured managed-resolver service state proves the resolver
/// (or its hosting daemon) is live.
///
///   * Linux: `systemctl is-active` must print exactly `active`. (Byte-
///     identical to the pre-Wave-2 assertion.)
///   * macOS: `launchctl print system/com.rustynet.daemon` maps to active via
///     the same `state =`/`pid =` heuristic the relay validator uses.
///   * Windows: `Get-Service` Status must be `Running`.
fn managed_dns_service_active(platform: LiveLabPlatform, output: &str) -> bool {
    match platform {
        LiveLabPlatform::Linux => output.trim() == "active",
        LiveLabPlatform::MacOs => macos_launchctl_daemon_active(output),
        LiveLabPlatform::Windows => output.trim().eq_ignore_ascii_case("running"),
    }
}

/// Reduce `launchctl print system/<label>` output to an active/inactive
/// decision. Mirrors the relay validator's launchctl state heuristic:
/// `state = running|waiting|spawn scheduled` is active; a non-zero `pid =` is
/// the fallback; `Could not find service` / `service not loaded` is inactive.
fn macos_launchctl_daemon_active(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    if lower.contains("could not find service") || lower.contains("service not loaded") {
        return false;
    }
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("state =") {
            return matches!(
                rest.trim().to_ascii_lowercase().as_str(),
                "running" | "waiting" | "spawn scheduled"
            );
        }
    }
    output.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("pid =")
            && trimmed
                .split_once('=')
                .and_then(|(_, rest)| rest.trim().parse::<u32>().ok())
                .is_some_and(|pid| pid != 0)
    })
}

fn render_remote_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr} (stdout: {stdout})")
    } else if !stderr.is_empty() {
        stderr.to_owned()
    } else if !stdout.is_empty() {
        format!("stdout: {stdout}")
    } else {
        "remote command exited non-zero without output".to_owned()
    }
}

fn json_field(root_dir: &Path, payload: &str, field: &str) -> Result<String, String> {
    run_cargo_ops_capture(
        root_dir,
        "read-json-field",
        &["--payload", payload, "--field", field],
    )
    .map(|value| value.trim().to_owned())
}

fn extract_managed_dns_expected_ip(
    root_dir: &Path,
    fqdn: &str,
    inspect_output: &str,
) -> Result<String, String> {
    run_cargo_ops_capture(
        root_dir,
        "extract-managed-dns-expected-ip",
        &["--fqdn", fqdn, "--inspect-output", inspect_output],
    )
    .map(|value| value.trim().to_owned())
}

fn write_env_file(path: &Path, entries: &[(&str, &str)]) -> Result<(), String> {
    let mut body = String::new();
    for (key, value) in entries {
        body.push_str(&format_env_assignment(key, value)?);
        body.push('\n');
    }
    write_secure_text(path, &body)
}

fn format_env_assignment(key: &str, value: &str) -> Result<String, String> {
    validate_env_key(key)?;
    Ok(format!("{key}={}", quote_env_value(value)?))
}

fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(format!("invalid env key: {key}"));
    }
    Ok(())
}

fn quote_env_value(value: &str) -> Result<String, String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err("env value must not contain newline or NUL characters".to_owned());
    }
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '$' => quoted.push_str("\\$"),
            '`' => quoted.push_str("\\`"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn ensure_safe_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-')
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

fn ensure_safe_spec(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-' | '|' | ';'
            )
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ManagedPeerSpec {
    node_id: String,
    host: String,
    platform: live_lab_support::LiveLabPlatform,
}

#[derive(Debug, Clone)]
struct ManagedPeerRuntime {
    node_id: String,
    address: String,
    pubkey_hex: String,
}

fn parse_managed_peer_spec(value: &str) -> Result<ManagedPeerSpec, String> {
    let trimmed = value.trim();
    let (node_id_raw, rest) = trimmed.split_once('|').ok_or_else(|| {
        format!(
            "invalid --managed-peer value (expected <node-id>|<user@host>[|<platform>]): {value}"
        )
    })?;
    // The host field may itself carry a trailing `|<platform>`. Split off at
    // most one more `|` so the platform field is optional: a 2-field legacy
    // value (`<node-id>|<host>`) defaults to Linux for backward compatibility.
    let (host_raw, platform) = match rest.split_once('|') {
        Some((host_raw, platform_raw)) => {
            let platform = live_lab_support::LiveLabPlatform::parse(platform_raw.trim())?;
            (host_raw, platform)
        }
        None => (rest, live_lab_support::LiveLabPlatform::Linux),
    };
    let node_id = node_id_raw.trim();
    let host = host_raw.trim();
    if node_id.is_empty() || host.is_empty() {
        return Err(format!(
            "invalid --managed-peer value (node-id and host must be non-empty): {value}"
        ));
    }
    Ok(ManagedPeerSpec {
        node_id: node_id.to_owned(),
        host: host.to_owned(),
        platform,
    })
}

/// Per-OS on-disk location of the signed assignment bundle. Mirrors the
/// per-platform paths encoded by `rustynet_assignment_bundle_path` in
/// `scripts/e2e/live_lab_common.sh`. Used to READ (cat) the bundle from a
/// managed peer for authority-scope parsing; the content is still parsed and
/// verified identically regardless of OS.
fn assignment_bundle_path(platform: live_lab_support::LiveLabPlatform) -> &'static str {
    match platform {
        live_lab_support::LiveLabPlatform::Linux => "/var/lib/rustynet/rustynetd.assignment",
        live_lab_support::LiveLabPlatform::MacOs => {
            "/usr/local/var/rustynet/trust/rustynetd.assignment"
        }
        live_lab_support::LiveLabPlatform::Windows => {
            r"C:\ProgramData\RustyNet\trust\rustynetd.assignment"
        }
    }
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn utc_now_string() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_owned()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn git_commit(root_dir: &Path) -> String {
    if let Ok(value) = env::var("RUSTYNET_EXPECTED_GIT_COMMIT") {
        return value.trim().to_lowercase();
    }
    let output = Command::new("git")
        .current_dir(root_dir)
        .args(["rev-parse", "HEAD"])
        .output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase(),
        _ => "unknown".to_owned(),
    }
}

fn require_command(command: &str) -> Result<(), String> {
    let status = Command::new("sh")
        .args([
            "-lc",
            &format!("command -v {} >/dev/null 2>&1", shell_single_quote(command)),
        ])
        .status()
        .map_err(|err| format!("failed to probe command {command}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
    }
}

fn parse_status_field(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status.split_whitespace().find_map(|token| {
        token
            .strip_prefix(prefix.as_str())
            .map(std::string::ToString::to_string)
    })
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_managed_dns_test --ssh-identity-file <path> [options]\n\noptions:\n  --signer-host <user@host>\n  --client-host <user@host>\n  --signer-node-id <id>\n  --client-node-id <id>\n  --managed-peer <node-id|user@host>   (repeatable)\n  --ssh-allow-cidrs <cidrs>\n  --report-path <path>\n  --log-path <path>\n  --zone-name <name>\n  --dns-interface <name>\n  --dns-bind-addr <ip:port>"
    );
}

#[cfg(test)]
mod tests {
    use super::live_lab_support::LiveLabPlatform;
    use super::{
        Config, ManagedDnsRecordTemplate, ManagedPeerSpec, assignment_bundle_path,
        dns_inspect_matches_expected_state, dns_inspect_readback_ready, dns_query_failed_closed,
        macos_launchctl_daemon_active, macos_scutil_advertises_managed_zone,
        managed_dns_distribution_targets, managed_dns_invalid_state_observed,
        managed_dns_replay_records, managed_dns_service_active, os_resolver_answer_contains_ip,
        parse_assignment_authority_scope, parse_managed_peer_spec, parse_status_field,
        resolver_config_advertises_managed_zone, rewrite_bundle_line_value,
        rewrite_bundle_signature, sorted_node_host_pairs, validate_targets,
        windows_dns_client_lists_loopback_server,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn base_config() -> Config {
        Config {
            platform: super::live_lab_support::LiveLabPlatform::Linux,
            ssh_identity_file: "/tmp/rn-test-key".to_owned(),
            known_hosts_file: None,
            signer_host: "debian@192.168.64.22".to_owned(),
            client_host: "debian@192.168.64.24".to_owned(),
            signer_node_id: "exit-1".to_owned(),
            client_node_id: "client-1".to_owned(),
            ssh_allow_cidrs: "192.168.64.0/24".to_owned(),
            report_path: PathBuf::from("/tmp/managed_dns_report.json"),
            log_path: PathBuf::from("/tmp/managed_dns_report.log"),
            zone_name: "rustynet".to_owned(),
            dns_interface: "rustynet0".to_owned(),
            dns_bind_addr: "127.0.0.1:53535".to_owned(),
            managed_peers: Vec::new(),
        }
    }

    #[test]
    fn parse_managed_peer_spec_accepts_node_id_and_host() {
        let parsed = parse_managed_peer_spec("client-2|debian@192.168.64.26")
            .expect("managed peer should parse");
        assert_eq!(parsed.node_id, "client-2");
        assert_eq!(parsed.host, "debian@192.168.64.26");
        // A 2-field legacy value defaults to Linux for backward compatibility.
        assert_eq!(parsed.platform, LiveLabPlatform::Linux);
    }

    #[test]
    fn parse_managed_peer_spec_parses_platform_field_and_maps_macos_bundle_path() {
        let macos = parse_managed_peer_spec("aux-1|macuser@192.168.64.30|macos")
            .expect("3-field managed peer should parse");
        assert_eq!(macos.node_id, "aux-1");
        assert_eq!(macos.host, "macuser@192.168.64.30");
        assert_eq!(macos.platform, LiveLabPlatform::MacOs);

        // A 2-field legacy value defaults to Linux.
        let legacy = parse_managed_peer_spec("client-9|debian@192.168.64.40")
            .expect("legacy 2-field managed peer should parse");
        assert_eq!(legacy.platform, LiveLabPlatform::Linux);

        // The macOS assignment bundle lives under the per-OS trust state root.
        assert_eq!(
            assignment_bundle_path(LiveLabPlatform::MacOs),
            "/usr/local/var/rustynet/trust/rustynetd.assignment"
        );
        assert_eq!(
            assignment_bundle_path(LiveLabPlatform::Linux),
            "/var/lib/rustynet/rustynetd.assignment"
        );
    }

    #[test]
    fn parse_managed_peer_spec_rejects_invalid_shape() {
        let err = parse_managed_peer_spec("client-2:debian@192.168.64.26").expect_err("must fail");
        assert!(
            err.contains("expected <node-id>|<user@host>"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_targets_rejects_duplicate_managed_peer_node_id() {
        let mut config = base_config();
        config.managed_peers.push(ManagedPeerSpec {
            node_id: "client-1".to_owned(),
            host: "debian@192.168.64.26".to_owned(),
            platform: LiveLabPlatform::Linux,
        });
        let err = validate_targets(&config).expect_err("duplicate node id must fail");
        assert!(
            err.contains("duplicates an existing node id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_targets_rejects_duplicate_managed_peer_host() {
        let mut config = base_config();
        config.managed_peers.push(ManagedPeerSpec {
            node_id: "client-2".to_owned(),
            host: "debian@192.168.64.22".to_owned(),
            platform: LiveLabPlatform::Linux,
        });
        let err = validate_targets(&config).expect_err("duplicate host must fail");
        assert!(
            err.contains("duplicates an existing host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_status_field_extracts_exit_node() {
        let status = "node_id=client-1 node_role=client state=ExitActive exit_node=client-2 dns_zone_state=valid";
        let exit = parse_status_field(status, "exit_node").expect("exit_node missing");
        assert_eq!(exit, "client-2");
    }

    #[test]
    fn parse_status_field_returns_none_when_missing() {
        let status = "node_id=client-1 node_role=client state=ExitActive";
        assert!(parse_status_field(status, "exit_node").is_none());
    }

    #[test]
    fn sorted_node_host_pairs_returns_deterministic_order() {
        let mut host_by_node = HashMap::new();
        host_by_node.insert("client-3".to_owned(), "debian@192.168.64.28".to_owned());
        host_by_node.insert("exit-1".to_owned(), "debian@192.168.64.22".to_owned());
        host_by_node.insert("client-1".to_owned(), "debian@192.168.64.24".to_owned());
        host_by_node.insert("client-2".to_owned(), "debian@192.168.64.26".to_owned());

        let ordered = sorted_node_host_pairs(&host_by_node);

        assert_eq!(
            ordered,
            vec![
                ("client-1".to_owned(), "debian@192.168.64.24".to_owned()),
                ("client-2".to_owned(), "debian@192.168.64.26".to_owned()),
                ("client-3".to_owned(), "debian@192.168.64.28".to_owned()),
                ("exit-1".to_owned(), "debian@192.168.64.22".to_owned()),
            ]
        );
    }

    #[test]
    fn managed_dns_distribution_targets_excludes_client_host() {
        let mut host_by_node = HashMap::new();
        host_by_node.insert("exit-1".to_owned(), "debian@192.168.64.22".to_owned());
        host_by_node.insert("client-1".to_owned(), "debian@192.168.64.24".to_owned());
        host_by_node.insert("client-2".to_owned(), "debian@192.168.64.26".to_owned());

        let targets = managed_dns_distribution_targets(&host_by_node, "debian@192.168.64.24");

        assert_eq!(
            targets,
            vec![
                ("client-2".to_owned(), "debian@192.168.64.26".to_owned()),
                ("exit-1".to_owned(), "debian@192.168.64.22".to_owned()),
            ]
        );
    }

    #[test]
    fn parse_assignment_authority_scope_collects_subject_and_peers() {
        let bundle = "\
version=1
node_id=client-2
peer_count=2
peer.0.node_id=client-1
peer.1.node_id=exit-1
signature=test
";

        let scope =
            parse_assignment_authority_scope(bundle).expect("assignment authority should parse");

        assert_eq!(scope.node_id, "client-2");
        assert_eq!(
            scope.peer_node_ids,
            vec!["client-1".to_owned(), "exit-1".to_owned()]
        );
    }

    #[test]
    fn parse_assignment_authority_scope_rejects_missing_subject() {
        let bundle = "\
version=1
peer.0.node_id=exit-1
";

        let err = parse_assignment_authority_scope(bundle).expect_err("missing node_id must fail");
        assert!(err.contains("missing node_id"), "unexpected error: {err}");
    }

    #[test]
    fn managed_dns_replay_records_adds_probe_alias_to_signer_record() {
        let records = vec![
            ManagedDnsRecordTemplate {
                label: "exit".to_owned(),
                target_node_id: "exit-1".to_owned(),
                ttl_secs: 300,
                aliases: vec!["gateway".to_owned()],
            },
            ManagedDnsRecordTemplate {
                label: "client".to_owned(),
                target_node_id: "client-1".to_owned(),
                ttl_secs: 300,
                aliases: Vec::new(),
            },
        ];

        let replay =
            managed_dns_replay_records(&records, "exit-1").expect("replay records should build");

        assert_eq!(
            replay[0].aliases,
            vec!["gateway".to_owned(), "gatewayreplay".to_owned()]
        );
        assert!(replay[1].aliases.is_empty());
    }

    #[test]
    fn rewrite_bundle_line_value_updates_requested_field() {
        let bundle = "\
version=1
record.0.fqdn=exit.rustynet
signature=abcd
";

        let rewritten = rewrite_bundle_line_value(bundle, "record.0.fqdn", "tampered.rustynet")
            .expect("bundle rewrite should succeed");

        assert!(rewritten.contains("record.0.fqdn=tampered.rustynet"));
        assert!(rewritten.contains("signature=abcd"));
    }

    #[test]
    fn rewrite_bundle_signature_rewrites_signature_hex() {
        let bundle = "\
version=1
record.0.fqdn=exit.rustynet
signature=abcd
";

        let rewritten =
            rewrite_bundle_signature(bundle, "0").expect("signature rewrite should succeed");

        assert!(rewritten.contains("signature=0000"));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_dns_inspect_reason_match() {
        assert!(managed_dns_invalid_state_observed(
            "dns inspect: state=invalid error=dns zone bundle replay detected",
            "",
            &["replay detected"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_dns_inspect_reason_with_underscores() {
        assert!(managed_dns_invalid_state_observed(
            "dns inspect: state=invalid error=dns_zone_bundle_subject_node_id_does_not_match_local_node",
            "",
            &["subject node id does not match local node"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_journal_reason_match() {
        assert!(managed_dns_invalid_state_observed(
            "",
            "dns zone preflight failed: dns zone bundle subject node id does not match local node",
            &["subject node id does not match local node"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_rejects_daemon_unreachable_without_invalid_state() {
        assert!(!managed_dns_invalid_state_observed(
            "daemon unreachable: inspect daemon socket failed (/run/rustynet/rustynetd.sock): No such file or directory",
            "",
            &["replay detected"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_skipped_preflight_journal_marker() {
        assert!(managed_dns_invalid_state_observed(
            "",
            "rustynetd startup warning: dns zone preflight skipped invalid managed DNS bundle: dns zone bundle replay detected",
            &["replay detected"]
        ));
    }

    #[test]
    fn dns_query_failed_closed_accepts_empty_payload_when_command_failed() {
        assert!(
            dns_query_failed_closed(Path::new("/tmp"), "", true)
                .expect("empty failed query should be accepted as fail-closed")
        );
    }

    #[test]
    fn dns_query_failed_closed_rejects_empty_payload_without_command_failure() {
        assert!(
            !dns_query_failed_closed(Path::new("/tmp"), "", false)
                .expect("empty successful query should not be treated as fail-closed")
        );
    }

    #[test]
    fn dns_inspect_readback_ready_rejects_daemon_unreachable_output() {
        assert!(!dns_inspect_readback_ready(
            "daemon unreachable: inspect daemon socket failed (/run/rustynet/rustynetd.sock): No such file or directory"
        ));
    }

    #[test]
    fn dns_inspect_readback_ready_accepts_invalid_state_output() {
        assert!(dns_inspect_readback_ready(
            "dns inspect: state=invalid error=dns zone bundle replay detected"
        ));
    }

    #[test]
    fn dns_inspect_matches_expected_state_enforces_requested_state() {
        assert!(dns_inspect_matches_expected_state(
            "dns inspect: state=valid zone_name=rustynet",
            Some("valid")
        ));
        assert!(!dns_inspect_matches_expected_state(
            "dns inspect: state=invalid error=signature verification failed",
            Some("valid")
        ));
        assert!(dns_inspect_matches_expected_state(
            "dns inspect: state=invalid error=signature verification failed",
            None
        ));
    }

    // ─── Wave 2 W2-D cross-OS resolver-stack parser coverage ───────────────

    const DNS_BIND_ADDR: &str = "127.0.0.1:53535";
    const DNS_SERVER: &str = "127.0.0.1";
    const ZONE: &str = "rustynet";
    const EXPECTED_IP: &str = "100.64.0.1";

    // --- split-DNS / resolver-configuration ---

    #[test]
    fn resolver_config_linux_resolvectl_status_matches_byte_identical() {
        // Realistic `resolvectl status rustynet0` excerpt: the link carries
        // the managed bind address plus the `~rustynet` routing domain.
        let output = "\
Link 4 (rustynet0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR
       DNS Servers: 127.0.0.1:53535
        DNS Domain: ~rustynet
";
        assert!(resolver_config_advertises_managed_zone(
            LiveLabPlatform::Linux,
            output,
            DNS_BIND_ADDR,
            DNS_SERVER,
            ZONE
        ));
        // Missing the routing domain must NOT pass (no split-DNS proof).
        let no_domain = "Link 4 (rustynet0)\n    DNS Servers: 127.0.0.1:53535\n";
        assert!(!resolver_config_advertises_managed_zone(
            LiveLabPlatform::Linux,
            no_domain,
            DNS_BIND_ADDR,
            DNS_SERVER,
            ZONE
        ));
    }

    #[test]
    fn resolver_config_macos_scutil_lists_managed_loopback_and_zone_domain() {
        // Realistic `scutil --dns` excerpt: the mesh resolver block scopes the
        // `rustynet` domain to the managed loopback nameserver.
        let output = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  flags    : Request A records

resolver #2
  domain   : rustynet
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Supplemental
  reach    : 0x00030002 (Reachable,Local Address)
";
        assert!(macos_scutil_advertises_managed_zone(
            output, DNS_SERVER, ZONE
        ));
        assert!(resolver_config_advertises_managed_zone(
            LiveLabPlatform::MacOs,
            output,
            DNS_BIND_ADDR,
            DNS_SERVER,
            ZONE
        ));
    }

    #[test]
    fn resolver_config_macos_scutil_fail_closed_when_zone_unscoped() {
        // A plain loopback forwarder with NO `domain : rustynet` line must not
        // masquerade as split-DNS — the zone-scope requirement guards that.
        let output = "\
resolver #1
  nameserver[0] : 127.0.0.1
  flags    : Request A records
";
        assert!(!macos_scutil_advertises_managed_zone(
            output, DNS_SERVER, ZONE
        ));
        // Empty output (scutil produced nothing) fails closed.
        assert!(!macos_scutil_advertises_managed_zone("", DNS_SERVER, ZONE));
    }

    #[test]
    fn resolver_config_windows_lists_managed_loopback_server() {
        // `Get-DnsClientServerAddress` rendered as `<ifAlias>=<server>` rows.
        let output = "Ethernet=127.0.0.1\nLoopback Pseudo-Interface 1=::1\n";
        assert!(windows_dns_client_lists_loopback_server(output, DNS_SERVER));
        assert!(resolver_config_advertises_managed_zone(
            LiveLabPlatform::Windows,
            output,
            DNS_BIND_ADDR,
            DNS_SERVER,
            ZONE
        ));
        // No interface points at the managed loopback resolver → fail closed.
        let off = "Ethernet=192.168.1.1\nWi-Fi=8.8.8.8\n";
        assert!(!windows_dns_client_lists_loopback_server(off, DNS_SERVER));
        assert!(!resolver_config_advertises_managed_zone(
            LiveLabPlatform::Windows,
            off,
            DNS_BIND_ADDR,
            DNS_SERVER,
            ZONE
        ));
    }

    // --- OS-resolver answer probe ---

    #[test]
    fn os_resolver_answer_linux_resolvectl_substring_match_is_byte_identical() {
        // `resolvectl query` prints `exit.rustynet: 100.64.0.1`.
        let output = "exit.rustynet: 100.64.0.1\n-- Information acquired via protocol DNS\n";
        assert!(os_resolver_answer_contains_ip(
            LiveLabPlatform::Linux,
            output,
            EXPECTED_IP
        ));
        assert!(!os_resolver_answer_contains_ip(
            LiveLabPlatform::Linux,
            "exit.rustynet: 10.0.0.5\n",
            EXPECTED_IP
        ));
    }

    #[test]
    fn os_resolver_answer_macos_dig_short_token_match() {
        // Combined `dig +short` / `dscacheutil` capture from capture_os_resolver_answer.
        let output = "\
dig +short:
100.64.0.1
dscacheutil:
name: exit.rustynet
ip_address: 100.64.0.1
";
        assert!(os_resolver_answer_contains_ip(
            LiveLabPlatform::MacOs,
            output,
            EXPECTED_IP
        ));
    }

    #[test]
    fn os_resolver_answer_macos_token_match_rejects_superstring_ip() {
        // `100.64.0.10` must NOT satisfy a check for `100.64.0.1` on the
        // token-exact mac/win path (defends against substring false-positives).
        let output = "dig +short:\n100.64.0.10\n";
        assert!(!os_resolver_answer_contains_ip(
            LiveLabPlatform::MacOs,
            output,
            EXPECTED_IP
        ));
    }

    #[test]
    fn os_resolver_answer_windows_resolve_dnsname_token_match() {
        // `Resolve-DnsName -Type A | Select -Expand IPAddress` then nslookup.
        let output = "\
100.64.0.1
nslookup:
Server:  UnKnown
Address:  127.0.0.1

Name:    exit.rustynet
Address:  100.64.0.1
";
        assert!(os_resolver_answer_contains_ip(
            LiveLabPlatform::Windows,
            output,
            EXPECTED_IP
        ));
        // A non-managed / NXDOMAIN answer has no expected IP token.
        assert!(!os_resolver_answer_contains_ip(
            LiveLabPlatform::Windows,
            "nslookup:\nServer:  UnKnown\n*** UnKnown can't find exit.rustynet\n",
            EXPECTED_IP
        ));
    }

    #[test]
    fn os_resolver_answer_empty_expected_ip_never_matches() {
        // A blank expected IP must fail closed on every OS — it can never be
        // satisfied by an empty answer.
        for platform in [
            LiveLabPlatform::Linux,
            LiveLabPlatform::MacOs,
            LiveLabPlatform::Windows,
        ] {
            assert!(!os_resolver_answer_contains_ip(
                platform,
                "100.64.0.1\n",
                ""
            ));
        }
    }

    // --- managed-resolver service-active ---

    #[test]
    fn managed_dns_service_active_linux_requires_exact_active() {
        assert!(managed_dns_service_active(
            LiveLabPlatform::Linux,
            "active\n"
        ));
        assert!(!managed_dns_service_active(
            LiveLabPlatform::Linux,
            "inactive\n"
        ));
        assert!(!managed_dns_service_active(
            LiveLabPlatform::Linux,
            "failed\n"
        ));
    }

    #[test]
    fn managed_dns_service_active_macos_launchctl_state_running() {
        let running = "\
com.rustynet.daemon = {
\tactive count = 1
\tstate = running
\tpid = 4821
}
";
        assert!(managed_dns_service_active(LiveLabPlatform::MacOs, running));
        assert!(macos_launchctl_daemon_active(running));
        // Not loaded → inactive.
        assert!(!managed_dns_service_active(
            LiveLabPlatform::MacOs,
            "Could not find service \"com.rustynet.daemon\" in domain for system\n"
        ));
    }

    #[test]
    fn managed_dns_service_active_macos_launchctl_pid_fallback() {
        // Truncated output with no `state =` line but a non-zero pid is active.
        let pid_only = "com.rustynet.daemon = {\n\tpid = 1337\n}\n";
        assert!(macos_launchctl_daemon_active(pid_only));
        // pid = 0 (scheduled but not running) is NOT active.
        let pid_zero = "com.rustynet.daemon = {\n\tpid = 0\n}\n";
        assert!(!macos_launchctl_daemon_active(pid_zero));
    }

    #[test]
    fn managed_dns_service_active_windows_requires_running() {
        assert!(managed_dns_service_active(
            LiveLabPlatform::Windows,
            "Running\n"
        ));
        assert!(!managed_dns_service_active(
            LiveLabPlatform::Windows,
            "Stopped\n"
        ));
        // Empty (service absent) fails closed.
        assert!(!managed_dns_service_active(LiveLabPlatform::Windows, ""));
    }
}
