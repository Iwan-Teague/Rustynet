#![forbid(unsafe_code)]

mod live_lab_support;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use live_lab_support::{
    LiveLabContext, LiveLabPlatform, Logger, ensure_dir_secure, repo_root, shell_single_quote,
    write_secure_json, write_secure_text,
};
use serde_json::json;

const LAN_TEST_INTERFACE: &str = "rnlan0";
const LAN_TEST_GATEWAY_IP: &str = "192.168.1.1/24";
const LAN_TEST_PROBE_IP: &str = "192.168.1.1";
const LAN_TEST_CIDR: &str = "192.168.1.0/24";
/// The tunnel interface the client routes LAN traffic over while LAN access is
/// coupled on, on Linux AND Windows. The daemon brings the WireGuard adapter up
/// as `rustynet0` on both (`DEFAULT_WG_INTERFACE`, `rustynetd::daemon`; the
/// Windows Wintun adapter alias is also `rustynet0` per
/// `rustynet-backend-wireguard`). The LAN-ON positive control asserts the LAN
/// route goes via this tunnel iface; the enforced-denial check asserts that same
/// tunnel route is withdrawn when LAN access is off (route absent / not via the
/// tunnel).
const TUNNEL_IFACE: &str = "rustynet0";
/// The macOS tunnel device prefix. macOS does NOT use a fixed `rustynet0` name —
/// the backend validator (`rustynet-backend-wireguard::macos_command`,
/// `rustynetd::macos_utun_helper`) requires the interface name to be `utun`
/// followed by digits (e.g. `utun9`), assigned dynamically by the kernel. The
/// macOS route parser therefore matches `utun<digits>` rather than a fixed name.
const MACOS_TUNNEL_IFACE_PREFIX: &str = "utun";
/// Canonical `inet` killswitch table name programmed by the daemon. Generation
/// rotation appends `_g<N>` (see `rustynetd::linux_runtime_nftables`), so the
/// matcher accepts both the bare and the rotated form.
const KILLSWITCH_INET_TABLE: &str = "rustynet";
/// macOS pf killswitch filter anchor prefix. The daemon loads the killswitch
/// into a generation-numbered anchor `com.apple/rustynet_g<N>`
/// (`MACOS_RUSTYNET_ANCHOR_PREFIX`, `rustynetd::macos_exit_killswitch_precedence`)
/// and the blind_exit posture into the fixed `com.rustynet/blind_exit` anchor
/// (`DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR`, `rustynetd::macos_blind_exit`). Either
/// anchor present in `pfctl -s Anchors` is positive evidence the fail-closed pf
/// machinery is loaded; the rendered killswitch ruleset also always terminates
/// in `block drop out quick all` (`render_macos_killswitch_pf_rules`).
const MACOS_KILLSWITCH_ANCHOR_PREFIX: &str = "com.apple/rustynet_g";
const MACOS_BLIND_EXIT_ANCHOR: &str = "com.rustynet/blind_exit";
const MACOS_KILLSWITCH_TERMINAL_RULE: &str = "block drop out quick all";
/// Windows killswitch evidence tokens. The daemon enforces the killswitch as a
/// default-deny outbound firewall posture (`netsh advfirewall ... firewallpolicy
/// blockoutbound`, surfaced as `DefaultOutboundAction : Block` on every profile)
/// plus the named allow rules `RustyNetKS-AllowLoopback` / `RustyNetKS-AllowEgress`
/// (`WINDOWS_KS_RULE_*`, `rustynetd::phase10`) and a native WFP tunnel-permit
/// sublayer. Either a `DefaultOutboundAction ... Block` profile line or a
/// `RustyNetKS-` rule name is positive enforcement evidence in firewall output.
const WINDOWS_KILLSWITCH_DEFAULT_OUTBOUND_BLOCK: &str = "DefaultOutboundAction";
const WINDOWS_KILLSWITCH_BLOCK_TOKEN: &str = "Block";
const WINDOWS_KILLSWITCH_RULE_PREFIX: &str = "RustyNetKS-";
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

/// Assignment bundle issuance is repeated during the convergence loop so that
/// `rustynet state refresh` calls on nodes never see a stale assignment bundle.
/// The daemon enforces `auto_tunnel_max_age_secs = 300` (5 min); without
/// periodic re-issuance the LAN-toggle stage would exceed that window.
#[derive(Clone, Copy)]
struct AssignmentRefreshConfig<'a> {
    signer_host: &'a str,
    exit_host: &'a str,
    client_host: &'a str,
    blind_exit_host: &'a str,
    env_local: &'a Path,
    assign_pub_local: &'a Path,
    exit_assignment_local: &'a Path,
    client_assignment_local: &'a Path,
    blind_exit_assignment_local: &'a Path,
    exit_node_id: &'a str,
    client_node_id: &'a str,
    blind_exit_node_id: &'a str,
    /// When true the CLIENT signs (and installs the verifier key of) its OWN
    /// assignment instead of receiving the exit-signed one.
    ///
    /// `rustynet ops apply-lan-access-coupling` makes the node re-issue its
    /// assignment with the node-local signing secret (the LAN routes live in
    /// that re-issued bundle), so the node under test must be its own
    /// assignment authority while the coupling is exercised. An exit-signed
    /// `assignment.pub` on the client belongs to ANOTHER authority: the refresh
    /// service rightly refuses to re-issue (katana-xnet-82 gate), and before
    /// the coupling learned to respect that it deleted the client's only
    /// bundle (katana-xnet-149). The exit and the blind-exit keep the
    /// exit-signed bundles, and `run()` re-installs the client's exit-signed
    /// pair (`client_self_signed: false`) before the stage ends so later
    /// stages find the lab's usual authority.
    client_self_signed: bool,
    /// Where the client's OWN verifier key is captured when
    /// `client_self_signed` is set.
    client_assign_pub_local: &'a Path,
}

#[derive(Clone, Copy)]
struct SignedStateRefreshConfig<'a> {
    assignment: AssignmentRefreshConfig<'a>,
    traversal: TraversalRefreshConfig<'a>,
    dns: DnsRefreshConfig<'a>,
    // When true, skip re-issuing assignment bundles. Use this during the LAN-ON
    // waiting phase: apply-lan-access-coupling just issued a fresh LAN assignment
    // (300s TTL), so re-issuing from the orchestrator env (which lacks LAN routes)
    // would overwrite it and reset lan_access to off on the next reconcile.
    skip_assignment_refresh: bool,
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

/// QH-57 choke-point validation: every spawner (the Rust stage wrapper, the
/// extended-soak stage, the bash orchestrator, manual invocation) funnels
/// through this binary, so the values that wedge a lab node are rejected
/// here regardless of caller.
///
/// Empty means the flag was omitted - there is deliberately no default (see
/// the parse block). A default-route entry would make the management bypass
/// cover everything and nothing: `apply_fail_closed_management_bypass_routes`
/// installs one underlay route per entry, and a `/0` entry claims the whole
/// address space while the full-tunnel default in the same table swallows
/// the real management LAN. An entry overlapping LAN_TEST_CIDR would put a
/// bypass route to the synthetic LAN's probe target into table 51820,
/// corrupting both the LAN-ON and LAN-OFF assertions this test exists for.
fn validate_ssh_allow_cidrs(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(
            "missing required argument: --ssh-allow-cidrs (pass the run's real \
             management CIDRs, e.g. 192.168.64.0/24; QH-57)"
                .to_owned(),
        );
    }
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry == "0.0.0.0/0" || entry == "::/0" {
            return Err(format!(
                "--ssh-allow-cidrs entry {entry} is a default route; on a \
                 full-tunnel node it cannot scope the management bypass (QH-57)"
            ));
        }
        if entry == LAN_TEST_CIDR {
            return Err(format!(
                "--ssh-allow-cidrs entry {entry} overlaps the synthetic \
                 LAN_TEST_CIDR; the toggle probes would ride the management \
                 bypass and corrupt the on/off assertions"
            ));
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let root_dir = repo_root()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut platform = live_lab_support::LiveLabPlatform::Linux;
    let mut exit_host = String::from("debian@192.168.18.49");
    let mut client_host = String::from("debian@192.168.18.65");
    let mut blind_exit_host = String::from("fedora@192.168.18.51");
    let mut exit_node_id = String::from("exit-49");
    let mut client_node_id = String::from("client-65");
    let mut blind_exit_node_id = String::from("client-51");
    // QH-57: deliberately NO default. The old default (192.168.18.0/24, the
    // bash-era lab LAN) is exactly the value that wedged the client: a
    // full-tunnel node derives its management bypass routes from this list,
    // and a list that covers none of the real underlay sends every
    // host<->guest packet - including the SSH session driving this test -
    // into the tunnel.
    let mut ssh_allow_cidrs = String::new();
    let mut ssh_identity_file = String::new();
    let mut report_path = root_dir.join("artifacts/phase10/live_linux_lan_toggle_report.json");
    let mut log_path = root_dir.join("artifacts/phase10/source/live_linux_lan_toggle.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--platform" => {
                idx += 1;
                platform = live_lab_support::LiveLabPlatform::parse(
                    required_value(&args, idx, "--platform")?.as_str(),
                )?;
            }
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
                print_usage();
                return Err(format!("unknown command: {other}"));
            }
        }
        idx += 1;
    }

    if ssh_identity_file.is_empty() {
        print_usage();
        return Err("missing required argument: --ssh-identity-file".to_owned());
    }
    validate_ssh_allow_cidrs(&ssh_allow_cidrs)?;

    // Wave 2 (W2-C): the lan-toggle / blind_exit stage is now cross-OS. The
    // Linux-only dispatcher gate is removed; `platform` is threaded through
    // every OS-specific probe/route/killswitch command and parser below so a
    // macOS or Windows invocation runs the REAL per-OS assertion logic (it will
    // pass or fail-closed honestly on a live guest) rather than failing at the
    // gate. The Linux command/parser branches are byte-identical to before.
    //
    // FAIL-CLOSED / honesty note: the SSH command transport in `live_lab_support`
    // wraps every argv in `sudo -n sh -lc <quoted>` (POSIX-only). On macOS this
    // is correct (sudo + sh are present). On WINDOWS this transport cannot run
    // PowerShell/cmd as-is — there is no `sudo`/`sh`, and the daemon IPC is a
    // named pipe, not a Unix socket — so a Windows invocation fails closed at
    // the daemon-socket / sudo preflight with a transport error rather than a
    // fake pass. This is flagged in the W2-C report as a daemon/transport-side
    // gap the live Windows run will expose; it is not papered over here.

    if let Some(parent) = report_path.parent() {
        ensure_dir_secure(parent)?;
    }
    if let Some(parent) = log_path.parent() {
        ensure_dir_secure(parent)?;
    }

    let logger = Logger::new(&log_path)?;
    let mut ctx = LiveLabContext::new(
        "rustynet-lan-toggle",
        PathBuf::from(&ssh_identity_file).as_path(),
    )?;
    let mut cleanup = LanToggleCleanup {
        ctx: ctx.clone(),
        exit_host: exit_host.clone(),
        dns_passphrase_remote: None,
        blind_exit_host: blind_exit_host.clone(),
        blind_exit_daemon_stopped: false,
        client_host: client_host.clone(),
        client_self_signed: false,
        exit_assign_pub_local: None,
        client_exit_assignment_local: None,
        refresh_env_snapshots: Vec::new(),
    };

    for host in [&exit_host, &client_host, &blind_exit_host] {
        ctx.push_sudo_password(host)?;
    }

    logger.line("Collecting WireGuard public keys")?;
    let exit_pub_hex = ctx.collect_pubkey_hex(&exit_host)?;
    let client_pub_hex = ctx.collect_pubkey_hex(&client_host)?;
    let blind_exit_pub_hex = ctx.collect_pubkey_hex(&blind_exit_host)?;

    let exit_addr = LiveLabContext::resolved_target_address(&exit_host)?;
    let client_addr = LiveLabContext::resolved_target_address(&client_host)?;
    let blind_exit_addr = LiveLabContext::resolved_target_address(&blind_exit_host)?;

    // blind_exit MUST NOT carry anchor capability (daemon rejects). Required
    // caps per NodeRole::BlindExit: blind_exit + exit_server.
    //
    // Node entry layout is node_id|endpoint|public_key|owner|hostname|os|
    // tags_csv|capabilities_csv. The assignment issuer reads capabilities from
    // field 7 (parse_assignment_nodes) while the traversal/DNS issuer reads
    // them from field 3, so the canonical lab form repeats the capability CSV
    // in field 3 and field 7 with the intervening fields empty (mirrors
    // build_onehop_specs). A bare node_id|endpoint|key|caps form puts caps in
    // the owner slot and leaves field 7 empty, so the assignment bundle
    // defaults every peer to client and the daemon rejects it ("route peer
    // <id> lacks signed relay_host or exit_server capability").
    let nodes_spec = format!(
        "{exit_node_id}|{exit_addr}:51820|{exit_pub_hex}|anchor,exit_server||||anchor,exit_server;{client_node_id}|{client_addr}:51820|{client_pub_hex}|client,relay_host||||client,relay_host;{blind_exit_node_id}|{blind_exit_addr}:51820|{blind_exit_pub_hex}|blind_exit,exit_server||||blind_exit,exit_server"
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
    )?;
    logger.line(format!(
        "Issuing signed LAN-toggle assignments on {exit_host}"
    ))?;
    issue_assignment_bundles_from_env(&ctx, &exit_host, &issue_env, "/tmp/rn_issue_lan.env")?;

    let assign_pub_local = ctx.work_dir.join("assignment.pub");
    let client_assign_pub_local = ctx.work_dir.join("assignment-client.pub");
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
    // Dedicated copy of the client's EXIT-SIGNED bundle: the self-signed swap
    // below overwrites `client_assignment_local` in place, so a mid-stage
    // failure needs its own pristine file to restore from. The exit verifier
    // key (`assign_pub_local`) is never overwritten by the self-signed
    // captures, so cleanup can reference it directly.
    let client_exit_assignment_local = ctx.work_dir.join("assignment-client-exit-signed");
    std::fs::copy(&client_assignment_local, &client_exit_assignment_local)
        .map_err(|err| format!("copy the client's exit-signed assignment bundle: {err}"))?;
    cleanup.exit_assign_pub_local = Some(assign_pub_local.clone());
    cleanup.client_exit_assignment_local = Some(client_exit_assignment_local);
    let exit_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&exit_assignment_local)
            .map_err(|err| err.to_string())?
            .as_str(),
    )?;
    let client_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&client_assignment_local)
            .map_err(|err| err.to_string())?
            .as_str(),
    )?;
    let blind_exit_scope = parse_assignment_authority_scope(
        std::fs::read_to_string(&blind_exit_assignment_local)
            .map_err(|err| err.to_string())?
            .as_str(),
    )?;

    logger.line("Distributing signed assignments")?;
    install_assignment_bundle(&ctx, &exit_host, &assign_pub_local, &exit_assignment_local)?;
    install_assignment_bundle(
        &ctx,
        &client_host,
        &assign_pub_local,
        &client_assignment_local,
    )?;
    // The blind-exit promotion is ATOMIC from the daemon's point of view:
    // the daemon is stopped before its signed assignment lands, so it can
    // never reconcile against a bundle that mismatches its current role or
    // the torn pub-then-bundle swap window (katana-u40: a still-client
    // daemon burned its five-reconcile budget in ~4s and restricted itself
    // permanently before the later enforce_host promotion could align it).
    // exit and client keep their roles, so their live-daemon installs are
    // intent-compatible and stay as-is.
    stop_daemon_for_atomic_promotion(&ctx, &blind_exit_host)?;
    cleanup.blind_exit_daemon_stopped = true;
    install_assignment_bundle(
        &ctx,
        &blind_exit_host,
        &assign_pub_local,
        &blind_exit_assignment_local,
    )?;

    // W7 toggle-env hygiene: snapshot each participant's pre-toggle
    // node-local refresh env + timer state BEFORE the toggle installs its
    // own narrowed env, and keep the snapshots on the cleanup guard so every
    // exit path (strict success restore below, best-effort Drop backstop)
    // can undo the install. A capture failure aborts here, before any node
    // is mutated with the toggle env.
    logger.line("Capturing pre-toggle node-local assignment-refresh state")?;
    let refresh_env_snapshots: Vec<RefreshEnvSnapshot> =
        [&exit_host, &client_host, &blind_exit_host]
            .into_iter()
            .map(|host| {
                capture_refresh_env_snapshot(&ctx, host).map_err(|err| {
                    format!("capture pre-toggle assignment-refresh state on {host}: {err}")
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
    cleanup.refresh_env_snapshots = refresh_env_snapshots.clone();
    for snapshot in &refresh_env_snapshots {
        logger.line(format!(
            "pre-toggle refresh state on {}: env={}, timer={}",
            snapshot.host,
            if snapshot.env_body.is_some() {
                "present"
            } else {
                "absent"
            },
            snapshot
                .timer_is_active_raw
                .as_deref()
                .unwrap_or("unknown")
                .trim(),
        ))?;
    }

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
    // Still inside the stopped-daemon window: the node-local refresh env
    // must be in place before the daemon comes back so its first refresh
    // already agrees with the installed assignment.
    install_assignment_refresh_env(&ctx, &blind_exit_host, &blind_exit_refresh_local)?;

    let traversal_env = ctx.work_dir.join("rn_issue_lan_traversal.env");
    write_assignment_env(
        &traversal_env,
        &[
            ("NODES_SPEC", &nodes_spec),
            ("ALLOW_SPEC", &allow_spec),
            (
                "TRAVERSAL_TTL_SECS",
                live_lab_support::LAB_TRAVERSAL_TTL_SECS,
            ),
        ],
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
    )?;
    write_secure_text(
        &client_dns_records_local,
        &managed_dns_records_manifest_for_scope(&dns_base_records, &client_scope)?,
    )?;
    write_secure_text(
        &blind_exit_dns_records_local,
        &managed_dns_records_manifest_for_scope(&dns_base_records, &blind_exit_scope)?,
    )?;
    let dns_passphrase_remote = ctx
        .capture_root(
            &exit_host,
            &["mktemp", "/run/rn-lan-toggle-dns-passphrase.XXXXXX"],
        )?
        .trim()
        .to_owned();
    ctx.run_root(
        &exit_host,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "ops",
            "materialize-signing-passphrase",
            "--output",
            dns_passphrase_remote.as_str(),
        ],
    )?;
    ctx.run_root(
        &exit_host,
        &["chmod", "0600", dns_passphrase_remote.as_str()],
    )?;
    ctx.run_root(
        &exit_host,
        &["install", "-d", "-m", "0700", DNS_ZONE_ISSUE_DIR],
    )?;
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
        assignment: AssignmentRefreshConfig {
            signer_host: exit_host.as_str(),
            exit_host: exit_host.as_str(),
            client_host: client_host.as_str(),
            blind_exit_host: blind_exit_host.as_str(),
            env_local: issue_env.as_path(),
            assign_pub_local: assign_pub_local.as_path(),
            exit_assignment_local: exit_assignment_local.as_path(),
            client_assignment_local: client_assignment_local.as_path(),
            blind_exit_assignment_local: blind_exit_assignment_local.as_path(),
            exit_node_id: exit_node_id.as_str(),
            client_node_id: client_node_id.as_str(),
            blind_exit_node_id: blind_exit_node_id.as_str(),
            // The SECOND refresh (after the negative control below) hands the
            // client its OWN assignment authority for the LAN-coupling
            // phases; see `AssignmentRefreshConfig`.
            client_self_signed: true,
            client_assign_pub_local: client_assign_pub_local.as_path(),
        },
        traversal: traversal_refresh,
        dns: DnsRefreshConfig {
            signer_host: exit_host.as_str(),
            dns_verifier_local: dns_verifier_local.as_path(),
            passphrase_remote: dns_passphrase_remote.as_str(),
            nodes_spec: nodes_spec.as_str(),
            allow_spec: allow_spec.as_str(),
            targets: &dns_targets,
        },
        skip_assignment_refresh: false,
    };
    // Enforce runtime roles BEFORE the first signed-state refresh. The
    // blind_exit node transitions from its prior client role into blind_exit
    // here, and `rustynet state refresh` validates the freshly distributed
    // assignment intent against the daemon's CURRENT enforced role. If the
    // refresh ran first, the still-client blind_exit daemon would reject its
    // blind_exit-intent assignment ("assignment target intent lacks required
    // local capability client"). enforce_host installs each node's target role
    // (reading the bundles distributed above), so the subsequent refresh
    // validates against the correct roles.
    logger.line("Enforcing runtime roles")?;
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

    // Fence the node-local assignment-refresh units out of the swap window.
    // Every guest runs rustynetd-assignment-refresh.timer (60s cadence) whose
    // ExecStart self-issues and installs a fresh signed assignment/traversal
    // pair from the node-local env. Left running, it races the exit-signed
    // pairs this test distributes: in katana-u23 an aux-node timer run
    // installed its self-signed verifier (pub mtime 01:22:45.596) between
    // this test's cycle-B bundle installs, so the daemon read a verifier and
    // a bundle signed by DIFFERENT keys, failed signature verification, hit
    // "traversal state missing while peers are managed" (rustynetd
    // refresh_signed_state_with_reason), escalated to restrict_permanent
    // within ~6 seconds, and the stage failed. enforce_host re-arms the timer
    // (it reinstalls and starts the units), so the fence must engage here —
    // after the ensure_daemon_services_ready loop, before the FIRST artifact
    // distribution — and hold until the whole toggle sequence is done. This
    // is the same hazard live_linux_two_hop_test fenced at swap time; the
    // LAN-toggle test never got the fence. Unlike two_hop the daemon STAYS
    // up: every subsequent step drives it through the IPC socket.
    logger.line("Quiescing node-local assignment-refresh units for the bundle swap")?;
    let bundle_swap_fence =
        BundleSwapFence::quiesce(&ctx, &[&exit_host, &client_host, &blind_exit_host])?;

    logger
        .line("Issuing and distributing fresh signed traversal bundles for LAN-toggle topology")?;
    // Negative-control precondition: the LAN-coupling negative control below
    // must run while the client still holds the EXIT-SIGNED pair issued by
    // the exit (it is NOT its own assignment authority), so this first
    // refresh explicitly keeps the client exit-signed even though the main
    // config swaps it to self-signed one refresh later.
    let signed_state_refresh_exit_signed = SignedStateRefreshConfig {
        assignment: AssignmentRefreshConfig {
            client_self_signed: false,
            ..signed_state_refresh.assignment
        },
        ..signed_state_refresh
    };
    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_exit_signed)?;

    // After enforce_host the daemons come up cold and stay in
    // restricted-safe mode until they ingest fresh signed trust
    // evidence. The route advertise call below is a mutating IPC
    // command and is refused while restricted-safe is set, so refresh
    // trust on every node first. Mirrors the equivalent step in
    // live_linux_two_hop_test (commit cca0418); without it
    // `route advertise 0.0.0.0/0` fails with "daemon is in
    // restricted-safe mode" on the exit and the LAN-toggle stage hard-
    // fails before the toggle is exercised at all.
    logger.line("Refreshing signed trust evidence on all nodes")?;
    refresh_trust_evidence(&ctx, &exit_host)?;
    refresh_trust_evidence(&ctx, &client_host)?;
    refresh_trust_evidence(&ctx, &blind_exit_host)?;

    // Negative control (review criterion C, exit-signed client): with the
    // client's installed assignment.pub belonging to the EXIT (so the client
    // is NOT its own assignment authority), enabling the LAN coupling must be
    // REFUSED with the kept-bundle explanation and must leave the installed
    // bundle byte-identical. The daemon must stay out of restricted-safe
    // mode: the refusal is a deliberate keep, not a reconcile failure.
    run_lan_coupling_negative_control(&ctx, &logger, platform, &client_host)?;
    // The refused coupling rewrites the client's node-local refresh env with
    // a --lan-routes line before the daemon rejects it; restore the env this
    // test installed so the self-signed swap below starts from the intended
    // state.
    install_assignment_refresh_env(&ctx, &client_host, &client_refresh_local)?;

    // The traversal coordination records inside each signed bundle have
    // a hard-capped 30-second TTL (MAX_COORDINATION_TTL_SECS in
    // crates/rustynetd/src/traversal.rs). Between the initial bundle
    // issuance at refresh_signed_state_artifacts above and now (post
    // enforce_host x3 + ensure_daemon_services_ready x3 + refresh_
    // trust_evidence x3) the coordination records have likely expired,
    // each daemon's reconcile loop fails repeatedly, and reconcile_
    // failures escalates to restriction_mode=Permanent (default
    // max_reconcile_failures=5). The route advertise that follows then
    // sees a Permanent-restricted daemon and is refused — the failure
    // mode that broke live_two_hop in livelab4 even with the trust
    // refresh in place.
    //
    // Re-issue traversal + DNS zone bundles, redistribute, then call
    // `state refresh` IPC on every node. State refresh is non-mutating
    // (exempt from the restricted-safe gate) and on success explicitly
    // resets restriction_mode to None and clears reconcile_failures
    // (daemon.rs:3506-3508). The route advertise that follows then
    // sees a daemon out of restricted-safe.
    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    // From here until the restore refresh below, the client runs its OWN
    // self-signed trust anchor; a mid-stage failure must put the exit-signed
    // pair back (LanToggleCleanup::drop, best-effort).
    cleanup.client_self_signed = true;
    log_reconcile_failures_after_trust_anchor_swap(
        &ctx,
        &logger,
        &client_host,
        "exit-signed -> self-signed swap",
    );

    logger.line("Advertising default route on exit")?;
    ctx.retry_root(
        &exit_host,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "route",
            "advertise",
            "0.0.0.0/0",
        ],
        10,
        2,
    )?;

    logger.line("Provisioning synthetic LAN subnet on exit")?;
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
    )?;
    ctx.run_root(&exit_host, &["ip", "link", "set", LAN_TEST_INTERFACE, "up"])?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    let client_status_off_initial = ctx.capture_root(
        &client_host,
        &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
    )?;
    logger.block("Initial client status", &client_status_off_initial)?;

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    let mut last_traversal_refresh_unix = unix_now();
    apply_lan_access(&ctx, platform, &client_host, false, LAN_TEST_CIDR)?;
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
        platform,
        &client_host,
        "blocked",
        45,
    )?;
    let client_status_off = ctx
        .capture_root(
            &client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    apply_lan_access(&ctx, platform, &client_host, true, LAN_TEST_CIDR)?;
    // Reset the traversal refresh timestamp after apply_lan_access returns: that
    // call may take >15s, which would cause maybe_refresh_signed_state_artifacts to
    // fire on the very first poll iteration and re-issue a no-LAN assignment from
    // the orchestrator env, immediately resetting lan_access to off.  Use a config
    // variant that skips assignment re-issuance for the duration of the LAN-ON
    // phase; traversal and DNS zone bundles are still refreshed as needed.
    last_traversal_refresh_unix = unix_now();
    let signed_state_refresh_lan_on = SignedStateRefreshConfig {
        skip_assignment_refresh: true,
        ..signed_state_refresh
    };
    let lan_on_state = wait_for_lan_access_state(
        &ctx,
        &logger,
        &signed_state_refresh_lan_on,
        &mut last_traversal_refresh_unix,
        &client_host,
        true,
        60,
    )?;
    let lan_on_ping_status = if lan_on_state {
        wait_for_lan_probe_state(
            &ctx,
            &logger,
            &signed_state_refresh_lan_on,
            &mut last_traversal_refresh_unix,
            platform,
            &client_host,
            "reachable",
            45,
        )?
    } else {
        false
    };
    let client_status_on = ctx
        .capture_root(
            &client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();
    let client_route_on = ctx
        .capture(&client_host, &route_to_target_argv(platform))
        .unwrap_or_default();

    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;
    last_traversal_refresh_unix = unix_now();
    apply_lan_access(&ctx, platform, &client_host, false, LAN_TEST_CIDR)?;
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
        platform,
        &client_host,
        "blocked",
        45,
    )?;
    let client_status_off_final = ctx
        .capture_root(
            &client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();

    // The client-side LAN-coupling phases are over: hand the client back to
    // the lab's usual assignment authority (the exit) so the stages after this
    // one find the exit-signed state they expect. This is the last artifact
    // refresh, and it sits inside the still-armed bundle-swap fence.
    let signed_state_refresh_restore = SignedStateRefreshConfig {
        assignment: AssignmentRefreshConfig {
            client_self_signed: false,
            ..signed_state_refresh.assignment
        },
        ..signed_state_refresh
    };
    refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_restore)?;
    // The client is back on the exit-signed pair: drop the cleanup restore.
    cleanup.client_self_signed = false;
    log_reconcile_failures_after_trust_anchor_swap(
        &ctx,
        &logger,
        &client_host,
        "self-signed -> exit-signed restore",
    );
    let blind_exit_denied_status =
        if apply_lan_access_expect_denied(&ctx, platform, &blind_exit_host, true, LAN_TEST_CIDR)? {
            "pass"
        } else {
            "fail"
        };
    let blind_exit_status = ctx
        .capture_root(
            &blind_exit_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();

    let client_plaintext_check = no_plaintext_passphrase_check(&ctx, &client_host)?;
    let exit_plaintext_check = no_plaintext_passphrase_check(&ctx, &exit_host)?;
    let blind_exit_plaintext_check = no_plaintext_passphrase_check(&ctx, &blind_exit_host)?;

    logger.block("Client status after LAN on", &client_status_on)?;
    logger.block("Client status after first LAN off", &client_status_off)?;
    logger.block("Client route to LAN probe after LAN on", &client_route_on)?;
    logger.block("Client status after LAN off", &client_status_off_final)?;
    logger.block("Blind exit status", &blind_exit_status)?;

    let check_lan_off_blocks = if lan_off_state && lan_off_ping_status {
        "pass"
    } else {
        "fail"
    };
    let check_lan_on_allows = if lan_on_state
        && lan_on_ping_status
        && client_status_on.contains("lan_access=on")
        && route_to_target_uses_tunnel(platform, &client_route_on)
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
    write_secure_json(&report_path, &report)?;

    logger.line(format!(
        "LAN toggle report written: {}",
        report_path.display()
    ))?;
    if overall != "pass" {
        return Err("LAN toggle test overall status: fail".to_owned());
    }
    // Released only after the full toggle sequence has succeeded; on any
    // earlier error path the armed guard's Drop restores every host instead.
    bundle_swap_fence.release()?;
    // W7 toggle-env hygiene, success path: STRICT restore of every
    // participant's pre-toggle node-local refresh env + timer disarm. The
    // stage must not pass while a narrowed env of its own making is still
    // installed and the refresh timer is armed: the next stage's full-fleet
    // pair swap would meet a tick that re-mints a traversal envelope from
    // the stale spec and the daemon fails closed on the QH-04 pair
    // invariant (katana-xnet-169). A failed restore fails the stage.
    logger.line("Restoring pre-toggle node-local assignment-refresh state")?;
    for snapshot in &cleanup.refresh_env_snapshots {
        restore_participant_refresh_state(&ctx, snapshot).map_err(|err| {
            format!(
                "restore pre-toggle assignment-refresh state on {}: {err}",
                snapshot.host
            )
        })?;
    }
    cleanup.refresh_env_snapshots = Vec::new();
    Ok(())
}

struct LanToggleCleanup {
    ctx: LiveLabContext,
    exit_host: String,
    dns_passphrase_remote: Option<String>,
    blind_exit_host: String,
    blind_exit_daemon_stopped: bool,
    client_host: String,
    /// True while the client's installed trust anchor is its OWN self-signed
    /// pair: set right after the swap refresh, cleared right after the
    /// restore refresh. Drives the best-effort exit-signed restore in `drop`.
    client_self_signed: bool,
    /// The exit verifier key (never overwritten by the self-signed captures).
    exit_assign_pub_local: Option<PathBuf>,
    /// Pristine copy of the client's exit-signed assignment bundle, taken
    /// before the self-signed swap overwrites the working capture file.
    client_exit_assignment_local: Option<PathBuf>,
    /// Pre-toggle node-local refresh state per participant, captured before
    /// the toggle installs its own env. Non-empty from the capture point
    /// until the success-path strict restore clears it; on every error path
    /// the Drop below restores it best-effort.
    refresh_env_snapshots: Vec<RefreshEnvSnapshot>,
}

impl Drop for LanToggleCleanup {
    fn drop(&mut self) {
        // W7 toggle-env hygiene backstop: on every error path, put each
        // participant's node-local refresh env back the way it was found
        // and stop the refresh timer, so no later stage can meet a timer
        // tick that re-mints a narrowed envelope over a fleet assignment
        // (the katana-xnet-169 QH-04 fail-closed chain). Best-effort by
        // design: Drop cannot fail; a failed restore is printed and leaves
        // the stage's own error as the primary failure.
        for snapshot in &self.refresh_env_snapshots {
            if let Err(err) = restore_participant_refresh_state(&self.ctx, snapshot) {
                eprintln!(
                    "cleanup: could not restore pre-toggle assignment-refresh state on {}: {err}",
                    snapshot.host
                );
            }
        }
        self.refresh_env_snapshots = Vec::new();
        // If the failure happened while the client ran its SELF-SIGNED trust
        // anchor, put the lab's exit-signed pair back best-effort so the next
        // stage finds the usual assignment authority. Best-effort by design:
        // Drop cannot fail, and the fence has already dropped at this point
        // (drop order is reverse declaration), so this restore can race a
        // resumed node-local refresh timer — a documented residual the timer
        // self-heals on its next 60s run.
        if self.client_self_signed {
            if let (Some(pub_local), Some(bundle_local)) = (
                self.exit_assign_pub_local.as_deref(),
                self.client_exit_assignment_local.as_deref(),
            ) {
                if let Err(err) = install_assignment_bundle_atomically(
                    &self.ctx,
                    &self.client_host,
                    pub_local,
                    bundle_local,
                ) {
                    eprintln!(
                        "cleanup: best-effort exit-signed assignment restore on {} failed: {err}",
                        self.client_host
                    );
                }
            }
            self.client_self_signed = false;
        }
        // The atomic blind-exit promotion stopped this daemon so its signed
        // assignment could be installed with no role/intent mismatch window.
        // `enforce_host` normally restarts it, but every earlier error path
        // lands here with the daemon still down; start it best-effort (a
        // no-op when it is already running) so no failure can strand the
        // guest daemonless for the next stage.
        if self.blind_exit_daemon_stopped {
            let _ = self.ctx.run_root_allow_failure(
                &self.blind_exit_host,
                &["systemctl", "start", "rustynetd.service"],
            );
        }
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
    platform: LiveLabPlatform,
    target: &str,
    enable: bool,
    lan_routes: &str,
) -> Result<(), String> {
    let output = run_lan_access_command(ctx, platform, target, enable, lan_routes, 20)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "apply-lan-access-coupling failed on {target}: {}",
            summarize_command_output(&output)
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn wait_for_lan_probe_state(
    ctx: &LiveLabContext,
    logger: &Logger,
    refresh_config: &SignedStateRefreshConfig<'_>,
    last_traversal_refresh_unix: &mut u64,
    platform: LiveLabPlatform,
    target: &str,
    desired_state: &str,
    attempts: u32,
) -> Result<bool, String> {
    for _ in 0..attempts {
        maybe_refresh_signed_state_artifacts(
            ctx,
            logger,
            refresh_config,
            last_traversal_refresh_unix,
        )?;
        let reachable = ctx.run(target, &lan_probe_argv(platform)).is_ok();
        if desired_state == "reachable" && reachable {
            return Ok(true);
        }
        if desired_state == "blocked" && !reachable {
            // F0.9 fail-closed: a bare ping failure is not proof of an enforced
            // denial — a transient loss, a downed iface, or a route flap also
            // produces `!reachable`. Pair the positive control (the same probe
            // IP is proven reachable in LAN-ON) with positive evidence that the
            // block is *caused by enforcement*: the client's tunnel route to the
            // LAN target has been withdrawn (route absent / not via the tunnel,
            // the inverse of the LAN-ON tunnel-route positive control), OR the
            // OS-native killswitch is present in the runtime ruleset (nft drop
            // table on Linux, pf block-all anchor on macOS, default-deny
            // outbound firewall on Windows). "blocked" requires BOTH
            // no-reachability AND enforcement evidence.
            if confirm_lan_block_enforced(ctx, logger, platform, target)? {
                return Ok(true);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(false)
}

/// Confirm that an observed LAN-probe block is caused by enforcement rather than
/// a coincidental timeout. Two independent, argv-only signals are collected from
/// the client and either is sufficient (both are honest enforcement evidence):
///
/// 1. The client's tunnel route to the LAN target is **withdrawn** — the OS route
///    query (`ip route get` on Linux, `route -n get` on macOS, `Get-NetRoute` on
///    Windows) no longer resolves the LAN probe over the rustynet tunnel device.
///    This is the exact inverse of the LAN-ON positive control, which requires
///    the route to go via the tunnel; withdrawing the advertised LAN route is
///    precisely how `ensure_lan_route_allowed` denies LAN access when it is
///    coupled off.
/// 2. The OS-native killswitch is present in the runtime ruleset — the `inet
///    rustynet[_g<N>]` nftables drop table on Linux, the `com.apple/rustynet_g<N>`
///    (or `com.rustynet/blind_exit`) pf block-all anchor on macOS, or the
///    default-deny outbound firewall posture / `RustyNetKS-` rule on Windows —
///    proving the fail-closed drop machinery is loaded.
///
/// Queries use `*_allow_failure` so a transient SSH/command hiccup never throws —
/// it simply yields no enforcement evidence on that poll, and the caller retries.
fn confirm_lan_block_enforced(
    ctx: &LiveLabContext,
    logger: &Logger,
    platform: LiveLabPlatform,
    target: &str,
) -> Result<bool, String> {
    let route_text = ctx
        .capture_root_allow_failure(target, &route_to_target_argv(platform))
        .unwrap_or_default();
    let tunnel_route_withdrawn = !route_to_target_uses_tunnel(platform, &route_text);

    let ruleset_text = ctx
        .capture_root_allow_failure(target, &killswitch_dump_argv(platform))
        .unwrap_or_default();
    let killswitch_present = killswitch_enforcement_present(platform, &ruleset_text);

    let enforced = tunnel_route_withdrawn || killswitch_present;
    logger.line(format!(
        "LAN block enforcement check on {target} ({}): tunnel_route_withdrawn={tunnel_route_withdrawn} killswitch_present={killswitch_present} enforced={enforced}",
        platform.as_str()
    ))?;
    Ok(enforced)
}

/// argv for the LAN reachability probe, per OS. Linux/macOS use BSD/GNU `ping`;
/// Windows drives `Test-Connection` through PowerShell.
///
/// - Linux: `ping -c 1 -W 1 <ip>` — `-W` is the per-reply timeout in seconds.
/// - macOS: `ping -c 1 -t 2 <ip>` — BSD `ping` uses `-t` as the total
///   give-up timeout in seconds (`-W` on BSD is the per-packet wait in ms and
///   differs from GNU semantics), so `-t 2` is the conventional bounded probe.
/// - Windows: `Test-Connection -Count 1 -Quiet -TimeoutSeconds 2` returns a
///   bare boolean, exit-coded by `if`. See the transport caveat in `run()`:
///   the POSIX `sudo -n sh -lc` wrapper means this argv will not execute as-is
///   on a Windows OpenSSH host — the Windows path fails closed at the transport
///   preflight, which is flagged in the W2-C report.
// REVIEW(W2-C): Windows `ping`-equivalent and its transport are unverified —
// the live Windows run must confirm the probe command and the cross-OS shell
// transport. There is no macOS/Windows LAN-toggle live binary in-repo yet to
// cross-check command shapes against.
fn lan_probe_argv(platform: LiveLabPlatform) -> Vec<&'static str> {
    match platform {
        LiveLabPlatform::Linux => vec!["ping", "-c", "1", "-W", "1", LAN_TEST_PROBE_IP],
        LiveLabPlatform::MacOs => vec!["ping", "-c", "1", "-t", "2", LAN_TEST_PROBE_IP],
        LiveLabPlatform::Windows => vec![
            "powershell",
            "-NoProfile",
            "-Command",
            "if (Test-Connection -ComputerName '192.168.1.1' -Count 1 -Quiet -TimeoutSeconds 2) { exit 0 } else { exit 1 }",
        ],
    }
}

/// argv to query the route to the LAN target, per OS.
///
/// - Linux: `ip -4 route get <ip>` — the canonical iproute2 single-route lookup.
/// - macOS: `route -n get <ip>` — BSD route lookup (mirrors the convention in
///   `rustynetd::macos_exit_dns_failclosed`); emits an `interface: utunN` line.
/// - Windows: `Get-NetRoute` filtered to the rustynet0 alias — a returned row
///   means the LAN route still resolves over the tunnel adapter.
// REVIEW(W2-C): the Windows route query relies on the POSIX-only transport (see
// `run()` caveat) and on the `rustynet0` Wintun alias being live; verify on a
// real Windows guest.
fn route_to_target_argv(platform: LiveLabPlatform) -> Vec<&'static str> {
    match platform {
        LiveLabPlatform::Linux => vec!["ip", "-4", "route", "get", LAN_TEST_PROBE_IP],
        LiveLabPlatform::MacOs => vec!["route", "-n", "get", LAN_TEST_PROBE_IP],
        LiveLabPlatform::Windows => vec![
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetRoute -DestinationPrefix '192.168.1.1/32' -InterfaceAlias 'rustynet0' -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders | Out-String -Width 32767",
        ],
    }
}

/// argv to dump the OS-native killswitch enforcement state, per OS.
///
/// - Linux: `nft list ruleset` — the full nftables ruleset; the matcher looks
///   for the `inet rustynet[_g<N>]` drop table.
/// - macOS: `pfctl -s Anchors` — lists the loaded pf anchors; the matcher looks
///   for the generation-numbered killswitch anchor `com.apple/rustynet_g<N>` or
///   the fixed blind_exit anchor `com.rustynet/blind_exit`. (The terminal
///   `block drop out quick all` rule is also accepted when a caller dumps the
///   anchor rules instead.)
/// - Windows: `Get-NetFirewallProfile` + the `RustyNetKS-` rules — the matcher
///   looks for a `DefaultOutboundAction ... Block` profile line or a
///   `RustyNetKS-` rule name.
// REVIEW(W2-C): the macOS `/sbin/pfctl` path and the Windows firewall query both
// depend on the cross-OS transport and on the daemon having loaded its
// killswitch; verify the exact command output shape on live guests.
fn killswitch_dump_argv(platform: LiveLabPlatform) -> Vec<&'static str> {
    match platform {
        LiveLabPlatform::Linux => vec!["nft", "list", "ruleset"],
        LiveLabPlatform::MacOs => vec!["pfctl", "-s", "Anchors"],
        LiveLabPlatform::Windows => vec![
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile -ErrorAction SilentlyContinue | Format-List Name,DefaultOutboundAction; Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'RustyNetKS-*' } | Format-Table -HideTableHeaders DisplayName | Out-String -Width 32767",
        ],
    }
}

/// True iff the route-query output resolves the LAN probe over the rustynet
/// tunnel device, per OS. Mirrors the LAN-ON positive control so the
/// enforced-denial check is its exact inverse. Empty/garbage input is treated as
/// "not via tunnel" (no positive evidence of a tunnel route), which fails closed
/// toward "route withdrawn" for the denial check.
///
/// - Linux: `ip route get` prints `... dev rustynet0 ...` — match a `dev
///   <TUNNEL_IFACE>` token pair (NOT a substring, so `rustynet0x` cannot match).
/// - macOS: `route -n get` prints an `interface: utunN` line — match an
///   `interface:` line whose value is `utun<digits>` (the dynamic tunnel name).
/// - Windows: `Get-NetRoute -InterfaceAlias rustynet0` prints a row only when the
///   route resolves over the tunnel adapter — any non-empty data row counts.
fn route_to_target_uses_tunnel(platform: LiveLabPlatform, route_get_output: &str) -> bool {
    match platform {
        LiveLabPlatform::Linux => route_get_output
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == TUNNEL_IFACE),
        LiveLabPlatform::MacOs => route_get_output.lines().any(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("interface:")
                .map(str::trim)
                .is_some_and(is_macos_utun_iface_name)
        }),
        LiveLabPlatform::Windows => {
            // `Get-NetRoute -InterfaceAlias rustynet0` already filtered to the
            // tunnel adapter; any non-empty, non-whitespace data row means the
            // route still resolves over the tunnel. (Headers are suppressed via
            // `-HideTableHeaders`.) An error / empty pipeline yields no rows.
            route_get_output.lines().any(|line| !line.trim().is_empty())
        }
    }
}

/// True iff `name` is a macOS utun tunnel interface name: the literal prefix
/// `utun` followed by one or more ASCII digits (e.g. `utun9`). `utun` alone,
/// `utunX`, or a substring like `xutun9` must NOT match.
fn is_macos_utun_iface_name(name: &str) -> bool {
    name.strip_prefix(MACOS_TUNNEL_IFACE_PREFIX)
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit()))
}

/// True iff the killswitch-dump output is positive evidence the OS-native
/// fail-closed drop machinery is loaded, per OS. Empty/garbage input yields false
/// (no enforcement evidence), so the caller falls back to the route-withdrawal
/// signal and otherwise keeps polling.
///
/// - Linux: the canonical `inet` killswitch table `rustynet` (or a
///   generation-rotated `rustynet_g<N>`) appears in `nft list ruleset`.
/// - macOS: the generation-numbered killswitch anchor `com.apple/rustynet_g<N>`
///   or the fixed blind_exit anchor `com.rustynet/blind_exit` appears in
///   `pfctl -s Anchors`, OR the terminal `block drop out quick all` rule appears
///   (when anchor rules are dumped instead).
/// - Windows: a firewall profile reports `DefaultOutboundAction ... Block`
///   (default-deny outbound) OR a `RustyNetKS-` allow rule is present.
fn killswitch_enforcement_present(platform: LiveLabPlatform, dump_output: &str) -> bool {
    match platform {
        LiveLabPlatform::Linux => killswitch_drop_table_present(dump_output),
        LiveLabPlatform::MacOs => macos_killswitch_anchor_present(dump_output),
        LiveLabPlatform::Windows => windows_killswitch_present(dump_output),
    }
}

/// Linux: true iff the runtime nftables ruleset contains the canonical `inet`
/// killswitch table (`rustynet` or a generation-rotated `rustynet_g<N>`).
fn killswitch_drop_table_present(ruleset_output: &str) -> bool {
    ruleset_output.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("table") {
            return false;
        }
        if tokens.next() != Some("inet") {
            return false;
        }
        match tokens.next() {
            Some(name) => {
                name == KILLSWITCH_INET_TABLE
                    || name
                        .strip_prefix(KILLSWITCH_INET_TABLE)
                        .and_then(|rest| rest.strip_prefix("_g"))
                        .is_some_and(|digits| {
                            !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
                        })
            }
            None => false,
        }
    })
}

/// macOS: true iff the killswitch dump shows the fail-closed pf machinery is
/// loaded — the generation-numbered killswitch anchor `com.apple/rustynet_g<N>`
/// (with a numeric generation) or the fixed blind_exit anchor
/// `com.rustynet/blind_exit` in `pfctl -s Anchors`, OR the terminal
/// `block drop out quick all` rule when anchor rules are dumped instead.
fn macos_killswitch_anchor_present(dump_output: &str) -> bool {
    dump_output.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed == MACOS_BLIND_EXIT_ANCHOR || trimmed.contains(MACOS_KILLSWITCH_TERMINAL_RULE) {
            return true;
        }
        // A killswitch anchor line is `com.apple/rustynet_g<digits>`; require a
        // non-empty numeric generation so the bare prefix or a confusable name
        // (e.g. `com.apple/rustynet_gX`) does not satisfy the check.
        trimmed
            .strip_prefix(MACOS_KILLSWITCH_ANCHOR_PREFIX)
            .is_some_and(|digits| {
                !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
            })
    })
}

/// Windows: true iff the firewall dump shows the killswitch is enforced — a
/// firewall profile with `DefaultOutboundAction ... Block` (default-deny
/// outbound posture) OR a `RustyNetKS-` allow rule name. A profile line whose
/// DefaultOutboundAction is `Allow`/`NotConfigured` is NOT enforcement evidence.
fn windows_killswitch_present(dump_output: &str) -> bool {
    dump_output.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.contains(WINDOWS_KILLSWITCH_RULE_PREFIX) {
            return true;
        }
        trimmed.contains(WINDOWS_KILLSWITCH_DEFAULT_OUTBOUND_BLOCK)
            && trimmed.contains(WINDOWS_KILLSWITCH_BLOCK_TOKEN)
    })
}

/// Assert the blind_exit node REFUSES LAN-access coupling. The denial is
/// transport-agnostic: `rustynet ops apply-lan-access-coupling` queries daemon
/// status, and when `node_role=blind_exit` it returns the exact error
/// `"LAN access coupling is not permitted for blind_exit role"` BEFORE any
/// OS-specific dataplane mutation (`rustynet-cli/src/main.rs`,
/// `execute_ops_apply_lan_access_coupling`). The same string is emitted on every
/// OS, so this assertion is portable — provided the command transport reaches
/// the daemon and the daemon reports the blind_exit role.
///
/// blind_exit dataplane caveat (flagged in the W2-C report): the macOS daemon
/// enforces the blind_exit pf posture (`com.rustynet/blind_exit` anchor), but the
/// Windows daemon dataplane IGNORES the blind_exit flag
/// (`WindowsCommandSystem::apply_nat_forwarding` takes `_blind_exit` and drops
/// it) — there is no Windows blind_exit egress-block enforcement. The role-level
/// LAN-coupling refusal still holds cross-OS, but the live Windows run will
/// expose the missing dataplane enforcement.
fn apply_lan_access_expect_denied(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
    enable: bool,
    lan_routes: &str,
) -> Result<bool, String> {
    let output = run_lan_access_command(ctx, platform, target, enable, lan_routes, 20)?;
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
        Err(format!(
            "unexpected blind-exit LAN coupling failure on {target}: {}",
            summarize_command_output(&output)
        ))
    }
}

fn run_lan_access_command(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
    enable: bool,
    lan_routes: &str,
    socket_wait_attempts: u32,
) -> Result<Output, String> {
    // Gate on the daemon IPC endpoint being live before issuing the mutating
    // coupling command. Linux + macOS use a Unix domain socket (paths differ);
    // Windows uses a named pipe, which has no Unix-socket equivalent for the
    // POSIX `test -S` probe used by `wait_for_daemon_socket`, so we cannot
    // (and must not pretend to) gate it here — see the per-OS path helper.
    match daemon_socket_path(platform) {
        Some(socket_path) => {
            ctx.wait_for_daemon_socket(target, socket_path, socket_wait_attempts, 1)?;
        }
        None => {
            // REVIEW(W2-C): Windows has no Unix daemon socket to probe (the
            // daemon IPC is the named pipe \\.\pipe\RustyNet\rustynetd). The
            // POSIX `sudo -n sh -lc` transport in `live_lab_support` also cannot
            // drive the `rustynet.exe` CLI on a Windows OpenSSH host as-is, so
            // the subsequent `run_root_allow_failure` will surface a real
            // transport error (fail-closed) on a live Windows run rather than a
            // fabricated pass. Flagged as a daemon/transport-side gap.
        }
    }

    let enable_flag = if enable { "true" } else { "false" };
    // Per-OS refresh-env location, matching the shell lab
    // (live_lab_common.sh assignment_refresh_env_path) and each OS's config
    // root: /etc/rustynet (Linux), /usr/local/etc/rustynet (macOS bootstrap
    // CONFIG_ROOT), C:\ProgramData\RustyNet\config (Windows).
    let env_path = live_lab_support::assignment_refresh_env_path(platform)?;
    let mut args = vec![
        live_lab_support::REMOTE_RUSTYNET_BIN,
        "ops",
        "apply-lan-access-coupling",
        "--enable",
        enable_flag,
        "--env-path",
        env_path,
    ];
    if !lan_routes.is_empty() {
        args.push("--lan-routes");
        args.push(lan_routes);
    }
    ctx.run_root_allow_failure(target, &args)
}

/// The daemon Unix-domain socket path used to gate mutating IPC, per OS, or
/// `None` when the OS has no Unix socket to probe.
///
/// - Linux: `/run/rustynet/rustynetd.sock` (`DEFAULT_SOCKET_PATH`, Linux build).
/// - macOS: `/private/var/run/rustynet/rustynetd.sock` (`DEFAULT_SOCKET_PATH`,
///   macOS build — `/var/run` is the `/private/var/run` symlink target).
/// - Windows: `None` — the daemon IPC is a named pipe
///   (`\\.\pipe\RustyNet\rustynetd`), not a Unix socket, so the POSIX
///   `test -S` daemon-socket probe does not apply.
fn daemon_socket_path(platform: LiveLabPlatform) -> Option<&'static str> {
    match platform {
        LiveLabPlatform::Linux => Some("/run/rustynet/rustynetd.sock"),
        LiveLabPlatform::MacOs => Some("/private/var/run/rustynet/rustynetd.sock"),
        LiveLabPlatform::Windows => None,
    }
}

fn summarize_command_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr} (stdout: {stdout})")
    } else if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no output".to_owned()
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
) -> Result<bool, String> {
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
        if let Ok(status) =
            ctx.capture_root(target, &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"])
            && status.contains(expected)
        {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(false)
}

fn no_plaintext_passphrase_check(ctx: &LiveLabContext, target: &str) -> Result<String, String> {
    let checks = [
        "/var/lib/rustynet/keys/wireguard.passphrase",
        "/etc/rustynet/wireguard.passphrase",
        "/etc/rustynet/signing_key_passphrase",
    ];
    for check in checks {
        ctx.run_root(target, &["test", "!", "-e", check])?;
    }
    Ok("no-plaintext-passphrase-files".to_owned())
}

fn write_assignment_env(path: &Path, items: &[(&str, &str)]) -> Result<(), String> {
    let mut contents = String::new();
    for (key, value) in items {
        contents.push_str(key);
        contents.push('=');
        contents.push_str(&quote_env_value(value)?);
        contents.push('\n');
    }
    write_secure_text(path, &contents)
}

fn quote_env_value(value: &str) -> Result<String, String> {
    if value.chars().any(|ch| ch == '\n' || ch == '\r') {
        return Err("invalid path: env value contains newline characters".to_owned());
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
) -> Result<(), String> {
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
        exit_node_storage = exit_node_id.to_owned();
        items.push(("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", &exit_node_storage));
    }
    write_assignment_env(path, &items)
}

fn capture_remote_file(
    ctx: &LiveLabContext,
    target: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let contents = ctx.capture_root(target, &["cat", remote_path])?;
    write_secure_text(local_path, &contents)
}

fn install_assignment_bundle(
    ctx: &LiveLabContext,
    target: &str,
    pubkey_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(pubkey_local, target, "/tmp/rn-assignment.pub")?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-assignment.bundle")?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())?;
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
    )?;
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
    )?;
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

/// Remote argv steps of the atomic client trust-anchor swap, pinned as consts
/// so the source-pin tests can assert the exact install/ownership/cleanup
/// steps without being perturbed by rustfmt.
const ASSIGNMENT_PUB_INSTALL_ARGS: [&str; 9] = [
    "install",
    "-m",
    "0644",
    "-o",
    "rustynetd",
    "-g",
    "root",
    "/tmp/rn-assignment.pub",
    "/etc/rustynet/assignment.pub",
];
const ASSIGNMENT_BUNDLE_INSTALL_ARGS: [&str; 9] = [
    "install",
    "-m",
    "0640",
    "-o",
    "root",
    "-g",
    "rustynetd",
    "/tmp/rn-assignment.bundle",
    "/var/lib/rustynet/rustynetd.assignment",
];
const ASSIGNMENT_SWAP_CLEANUP_ARGS: [&str; 5] = [
    "rm",
    "-f",
    "/var/lib/rustynet/rustynetd.assignment.watermark",
    "/tmp/rn-assignment.pub",
    "/tmp/rn-assignment.bundle",
];

/// Install an assignment trust-anchor pair (verifier key + signed bundle) in
/// ONE remote root shell: dir, pub install, bundle install and stale-watermark
/// cleanup are chained with `&&` so the daemon can never observe a torn
/// pub-then-bundle window. Splitting these into separate root commands is
/// what let the client daemon (whose 60s node-local refresh timer races the
/// test) reconcile a NEW verifier against the OLD bundle, fail signature
/// verification and burn its reconcile budget into a permanent restriction.
/// The watermark is only removed AFTER both halves installed: the refresh
/// service treats a missing watermark as "bundle still fresh", so removing it
/// early could tempt a concurrent refresh into a half-swapped state.
fn install_assignment_bundle_atomically(
    ctx: &LiveLabContext,
    target: &str,
    pubkey_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(pubkey_local, target, "/tmp/rn-assignment.pub")?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-assignment.bundle")?;
    let mut script = String::new();
    let steps: [&[&str]; 4] = [
        &etc_rustynet_install_dir_args(),
        &ASSIGNMENT_PUB_INSTALL_ARGS,
        &ASSIGNMENT_BUNDLE_INSTALL_ARGS,
        &ASSIGNMENT_SWAP_CLEANUP_ARGS,
    ];
    for step in steps {
        if !script.is_empty() {
            script.push_str(" && ");
        }
        let quoted: Vec<String> = step.iter().map(|arg| shell_single_quote(arg)).collect();
        script.push_str(&quoted.join(" "));
    }
    ctx.run_root(target, &["sh", "-c", &script])?;
    Ok(())
}

/// sha256 of a remote file, validated as a real 64-hex digest so a transport
/// error or an empty capture can never masquerade as "unchanged".
fn remote_file_sha256(ctx: &LiveLabContext, target: &str, path: &str) -> Result<String, String> {
    let output = ctx
        .capture_root(target, &["sha256sum", path])
        .map_err(|err| format!("sha256sum {path} on {target} failed: {err}"))?;
    let digest = output
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "sha256sum {path} on {target} did not yield a 64-hex digest: {output}"
        ));
    }
    Ok(digest)
}

const KEPT_BUNDLE_ERROR_MARKER: &str =
    "the existing assignment bundle was kept because this node is not its own assignment authority";

/// Run the LAN coupling on a node that keeps an external authority's bundle
/// and REQUIRE the kept-bundle refusal: success is a failure, a failure
/// without the kept-bundle explanation is a failure too (any other error
/// means the control observed something else entirely).
fn apply_lan_access_expect_kept_bundle(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
    enable: bool,
    lan_routes: &str,
) -> Result<(), String> {
    let output = run_lan_access_command(ctx, platform, target, enable, lan_routes, 20)?;
    if output.status.success() {
        return Err(format!(
            "apply-lan-access-coupling unexpectedly succeeded on {target} while the node keeps an external authority's bundle: {}",
            summarize_command_output(&output)
        ));
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !combined.contains(KEPT_BUNDLE_ERROR_MARKER) {
        return Err(format!(
            "apply-lan-access-coupling on {target} failed without the kept-bundle explanation: {combined}"
        ));
    }
    Ok(())
}

/// Negative control: on the exit-signed client (NOT its own assignment
/// authority) the LAN-ON coupling must be refused with the kept-bundle text,
/// must not modify the installed bundle, and must leave the daemon out of
/// restricted-safe mode (the refusal is a deliberate keep, not a restriction).
fn run_lan_coupling_negative_control(
    ctx: &LiveLabContext,
    logger: &Logger,
    platform: LiveLabPlatform,
    client_host: &str,
) -> Result<(), String> {
    let bundle_remote = "/var/lib/rustynet/rustynetd.assignment";
    let bundle_sha_before = remote_file_sha256(ctx, client_host, bundle_remote)?;
    apply_lan_access_expect_kept_bundle(ctx, platform, client_host, true, LAN_TEST_CIDR)
        .map_err(|err| format!("LAN-ON negative control did not behave as specified: {err}"))?;
    let bundle_sha_after = remote_file_sha256(ctx, client_host, bundle_remote)?;
    if bundle_sha_before != bundle_sha_after {
        return Err(format!(
            "the negative control's refused coupling must not touch the installed assignment bundle: sha {bundle_sha_before} -> {bundle_sha_after}"
        ));
    }
    let status = ctx
        .capture_root(
            client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();
    if !status.contains("restricted_safe_mode=false") {
        return Err(format!(
            "the negative control must leave the client daemon OUT of restricted-safe mode: {status}"
        ));
    }
    logger.line(
        "Negative control pass: LAN-ON coupling on the exit-signed client was refused with the kept-bundle text, bundle untouched, daemon healthy",
    )?;
    Ok(())
}

/// Log the client's reconcile_failures counter after a trust-anchor swap so a
/// future run's log shows whether the swap forced the daemon to burn its
/// reconcile budget (the katana-u23/u40 failure mode). Best-effort and
/// non-failing by design: diagnostics only.
fn log_reconcile_failures_after_trust_anchor_swap(
    ctx: &LiveLabContext,
    logger: &Logger,
    client_host: &str,
    swap: &str,
) {
    let status = ctx
        .capture_root_allow_failure(
            client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();
    let counter = status
        .lines()
        .find(|line| line.contains("reconcile_failures"))
        .map(|line| line.trim().to_owned())
        .unwrap_or_else(|| "reconcile_failures line absent".to_owned());
    let _ = logger.line(format!("client reconcile status after {swap}: {counter}"));
}

fn install_assignment_refresh_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(env_local, target, "/tmp/rn-assignment-refresh.env")?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())?;
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
    )?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", "/tmp/rn-assignment-refresh.env"]);
    Ok(())
}

/// The node-local assignment-refresh env path `install_assignment_refresh_env`
/// writes, and the systemd timer the node-local refresh service runs on. The
/// restore below must target exactly the path the toggle's install wrote.
const ASSIGNMENT_REFRESH_ENV_REMOTE: &str = "/etc/rustynet/assignment-refresh.env";
const ASSIGNMENT_REFRESH_TIMER_UNIT: &str = "rustynetd-assignment-refresh.timer";

/// The pre-toggle node-local refresh state of one participant, captured
/// BEFORE the toggle installs its own env, so every exit path (the strict
/// success-path restore and the [`LanToggleCleanup`] Drop backstop) can put
/// the node back the way it was found. katana-xnet-169: the toggle left its
/// narrowed 3-participant env installed and its timer armed, so the next
/// stage's full-fleet pair swap met a timer tick that re-minted a traversal
/// envelope missing the relay and the daemon failed closed on the QH-04
/// pair invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RefreshEnvSnapshot {
    host: String,
    /// `ASSIGNMENT_REFRESH_ENV_REMOTE` contents as found. None = the file
    /// did not exist (or was empty), so restore REMOVES the toggle's env.
    env_body: Option<String>,
    /// Raw `systemctl is-active` output for [`ASSIGNMENT_REFRESH_TIMER_UNIT`]
    /// as found ("active", "inactive", ...). None = the probe could not be
    /// read (e.g. no systemd on the guest); recorded for the log, never
    /// guessed.
    timer_is_active_raw: Option<String>,
}

impl RefreshEnvSnapshot {
    /// True only when `systemctl is-active` answered "active" as found. The
    /// success-path restore makes the timer stop STRICT only in this case:
    /// a timer that was already stopped or unknown cannot be left armed by
    /// a failed stop in any way that matters.
    fn timer_found_active(&self) -> bool {
        self.timer_is_active_raw
            .as_deref()
            .map(str::trim)
            .is_some_and(|state| state == "active")
    }
}

/// What restore must do to one participant's env file.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RefreshEnvRestoreAction {
    /// The env existed before the toggle: write the captured bytes back.
    Reinstall(String),
    /// No env existed (or it was empty) before the toggle: remove the
    /// toggle's env. A narrowed env left in place is the katana-xnet-169
    /// poison; absence is the state the node's next explicit env writer
    /// (the pair swap's resume path, enforce_host) expects.
    Remove,
}

/// Pure decision: which env action restores one participant. Empty/whitespace
/// captures count as absent (a zero-byte env is not a usable fleet env and
/// cannot be told apart from a failed cat).
fn refresh_env_restore_action(snapshot: &RefreshEnvSnapshot) -> RefreshEnvRestoreAction {
    match snapshot.env_body.as_deref() {
        Some(body) if !body.trim().is_empty() => {
            RefreshEnvRestoreAction::Reinstall(body.to_owned())
        }
        _ => RefreshEnvRestoreAction::Remove,
    }
}

/// The exact argv that disarms the refresh timer. Always executed on the
/// restore path: a resumed tick would run whatever env is installed against
/// the toggle's still-installed (narrowed) assignments and mint exactly the
/// traversal-wider-than-assignment half-pair the daemon must fail closed on.
/// Every stage that needs the timer re-arms it explicitly (the pair swap's
/// resume script, enforce_host), so "stopped" is the safe as-left state.
fn refresh_timer_disarm_argv() -> [&'static str; 3] {
    ["systemctl", "stop", ASSIGNMENT_REFRESH_TIMER_UNIT]
}

/// Read one participant's pre-toggle node-local refresh state. The env cat
/// is STRICT: if the as-found state cannot be read, the toggle aborts
/// BEFORE installing its own env rather than mutating a node it could not
/// snapshot (fail-closed capture). The timer probe is advisory and recorded
/// as None when it fails.
fn capture_refresh_env_snapshot(
    ctx: &LiveLabContext,
    host: &str,
) -> Result<RefreshEnvSnapshot, String> {
    let env_body =
        match ctx.capture_root_allow_failure(host, &["cat", ASSIGNMENT_REFRESH_ENV_REMOTE])? {
            body if body.trim().is_empty() => None,
            body => Some(body),
        };
    let timer_is_active_raw = match ctx.capture_root_allow_failure(
        host,
        &["systemctl", "is-active", ASSIGNMENT_REFRESH_TIMER_UNIT],
    ) {
        Ok(raw) => Some(raw),
        Err(err) => {
            eprintln!(
                "warning: could not read the {ASSIGNMENT_REFRESH_TIMER_UNIT} state on {host} \
                 (recording as unknown): {err}"
            );
            None
        }
    };
    Ok(RefreshEnvSnapshot {
        host: host.to_owned(),
        env_body,
        timer_is_active_raw,
    })
}

/// Restore one participant's pre-toggle node-local refresh state: env back
/// (or removed), then the refresh timer disarmed. The timer stop is strict
/// only when `systemctl is-active` answered "active" as found — that is the
/// one shape where a failed stop leaves the katana-xnet-169 poison window
/// (armed timer + env the toggle did not mint) genuinely open; any other
/// stop failure is warned and swallowed because the timer was not running
/// as found anyway. Runs on BOTH paths: the strict success-path call in
/// `run()` and the best-effort [`LanToggleCleanup`] Drop backstop.
fn restore_participant_refresh_state(
    ctx: &LiveLabContext,
    snapshot: &RefreshEnvSnapshot,
) -> Result<(), String> {
    let host = snapshot.host.as_str();
    match refresh_env_restore_action(snapshot) {
        RefreshEnvRestoreAction::Reinstall(body) => {
            let local = ctx
                .work_dir
                .join(format!("restore-assignment-refresh-{}.env", unix_now()));
            write_secure_text(&local, &body)?;
            install_assignment_refresh_env(ctx, host, &local)
                .map_err(|err| format!("reinstall captured assignment-refresh env: {err}"))?;
        }
        RefreshEnvRestoreAction::Remove => {
            ctx.run_root(host, &["rm", "-f", ASSIGNMENT_REFRESH_ENV_REMOTE])
                .map_err(|err| format!("remove {ASSIGNMENT_REFRESH_ENV_REMOTE}: {err}"))?;
        }
    }
    match ctx.run_root_allow_failure(host, &refresh_timer_disarm_argv()) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let err = format!(
                "systemctl stop {ASSIGNMENT_REFRESH_TIMER_UNIT} failed on {host}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            if snapshot.timer_found_active() {
                Err(err)
            } else {
                eprintln!("warning: {err} (timer was not active as found; tolerating)");
                Ok(())
            }
        }
        Err(err) => {
            let err = format!("systemctl stop {ASSIGNMENT_REFRESH_TIMER_UNIT}: {err}");
            if snapshot.timer_found_active() {
                Err(err)
            } else {
                eprintln!("warning: {err} (timer was not active as found; tolerating)");
                Ok(())
            }
        }
    }
}

fn install_traversal_bundle(
    ctx: &LiveLabContext,
    target: &str,
    pubkey_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(pubkey_local, target, "/tmp/rn-traversal.pub")?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-traversal.bundle")?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())?;
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
    )?;
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
    )?;
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
) -> Result<(), String> {
    ctx.scp_to(verifier_local, target, "/tmp/rn-dns-zone.pub")?;
    ctx.scp_to(bundle_local, target, "/tmp/rn-dns-zone.bundle")?;
    ctx.run_root(target, &etc_rustynet_install_dir_args())?;
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
    )?;
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
    )?;
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
) -> Result<(), String> {
    // Re-issue assignment bundles before refreshing state so that the daemon's
    // 300-second max-age check never sees a stale bundle during long convergence
    // loops that span multiple traversal refresh cycles.
    // Skip when apply-lan-access-coupling just issued a fresh LAN assignment:
    // re-issuing from the orchestrator env (which lacks LAN routes) would overwrite
    // it and immediately reset lan_access to off on the next reconcile.
    if !config.skip_assignment_refresh {
        refresh_assignment_bundles(ctx, logger, &config.assignment)?;
    }
    refresh_traversal_bundles(ctx, logger, &config.traversal)?;
    refresh_dns_zone_bundles(ctx, logger, &config.dns)?;
    for target in config.dns.targets {
        refresh_trust_evidence(ctx, target.host)?;
        refresh_signed_state_now(ctx, target.host)?;
    }
    Ok(())
}

fn refresh_assignment_bundles(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &AssignmentRefreshConfig<'_>,
) -> Result<(), String> {
    logger.line("Refreshing signed assignment bundles for LAN-toggle participants")?;
    issue_assignment_bundles_from_env(
        ctx,
        config.signer_host,
        config.env_local,
        "/tmp/rn_issue_lan.env",
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        config.assign_pub_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.exit_node_id
        ),
        config.exit_assignment_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.client_node_id
        ),
        config.client_assignment_local,
    )?;
    capture_remote_file(
        ctx,
        config.signer_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.blind_exit_node_id
        ),
        config.blind_exit_assignment_local,
    )?;
    if config.client_self_signed {
        // The client signs its OWN assignment (see `AssignmentRefreshConfig::
        // client_self_signed`): issue on the client with its node-local
        // signing secret and replace the exit-signed client bundle captured
        // above, together with the verifier key that goes with it.
        issue_assignment_bundles_from_env(
            ctx,
            config.client_host,
            config.env_local,
            "/tmp/rn_issue_lan.env",
        )?;
        capture_remote_file(
            ctx,
            config.client_host,
            "/run/rustynet/assignment-issue/rn-assignment.pub",
            config.client_assign_pub_local,
        )?;
        capture_remote_file(
            ctx,
            config.client_host,
            &format!(
                "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
                config.client_node_id
            ),
            config.client_assignment_local,
        )?;
    }
    install_assignment_bundle(
        ctx,
        config.exit_host,
        config.assign_pub_local,
        config.exit_assignment_local,
    )?;
    // The client's trust-anchor swap is ATOMIC on the guest: verifier key,
    // bundle and watermark cleanup land in ONE remote root shell so the
    // daemon (or its node-local refresh timer) can never reconcile a torn
    // pub-then-bundle state. The exit and blind-exit installs above keep
    // their plain form: their pub half is identical across refreshes (same
    // exit authority) and their daemons' roles are stable, so the torn
    // window this closes is client-specific.
    install_assignment_bundle_atomically(
        ctx,
        config.client_host,
        if config.client_self_signed {
            config.client_assign_pub_local
        } else {
            config.assign_pub_local
        },
        config.client_assignment_local,
    )?;
    install_assignment_bundle(
        ctx,
        config.blind_exit_host,
        config.assign_pub_local,
        config.blind_exit_assignment_local,
    )?;
    Ok(())
}

fn refresh_traversal_bundles(
    ctx: &LiveLabContext,
    logger: &Logger,
    config: &TraversalRefreshConfig<'_>,
) -> Result<(), String> {
    logger.line("Refreshing signed traversal bundles for LAN-toggle participants")?;
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
) -> Result<(), String> {
    logger.line("Refreshing signed DNS zone bundles for LAN-toggle participants")?;
    for target in config.targets {
        let remote_records = format!("/tmp/rn-lan-toggle-dns-records-{}.manifest", target.node_id);
        ctx.scp_to(
            target.records_local,
            config.signer_host,
            remote_records.as_str(),
        )?;
        ctx.run_root(
            config.signer_host,
            &[
                live_lab_support::REMOTE_RUSTYNET_BIN,
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
        )?;
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
) -> Result<(), String> {
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

fn refresh_signed_state(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    ctx.run_root(
        target,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "state",
            "refresh",
        ],
    )
    .map(|_| ())
}

fn refresh_signed_state_now(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)?;
    refresh_signed_state(ctx, target)
}

fn refresh_trust_evidence(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)?;
    ctx.run_root(
        target,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "ops",
            "refresh-signed-trust",
        ],
    )
    .map(|_| ())
}

fn issue_assignment_bundles_from_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), String> {
    ctx.scp_to(env_local, target, remote_env_path)?;
    ctx.run_root(
        target,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "ops",
            "e2e-issue-assignment-bundles-from-env",
            "--env-file",
            remote_env_path,
        ],
    )?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", remote_env_path]);
    Ok(())
}

fn issue_traversal_bundles_from_env(
    ctx: &LiveLabContext,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), String> {
    ctx.scp_to(env_local, target, remote_env_path)?;
    ctx.run_root(
        target,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "ops",
            "e2e-issue-traversal-bundles-from-env",
            "--env-file",
            remote_env_path,
        ],
    )?;
    let _ = ctx.run_root_allow_failure(target, &["rm", "-f", remote_env_path]);
    Ok(())
}

/// Stop the daemon on the to-be-promoted blind-exit host so its signed
/// assignment bundle is installed while NO daemon is reconciling.
///
/// Installing the blind_exit-intent assignment while the daemon still runs
/// as a client is not atomic today (pub-then-bundle over two scp targets):
/// the live daemon reconciles mid-swap, sees a bundle that mismatches either
/// its trust anchor (torn pub swap) or its current role ("assignment target
/// intent lacks required local capability client"), burns its
/// five-reconcile budget within seconds and restricts itself permanently —
/// all BEFORE the later `enforce_host` promotion could have aligned it
/// (katana-u40 aux journal 22:26:59-22:27:03 UTC). With the daemon stopped
/// the swap is invisible to it; the subsequent `enforce_host` call rewrites
/// the role config and starts the daemon straight into the aligned state.
/// `LanToggleCleanup` restarts it if any earlier error path skips enforcement.
fn stop_daemon_for_atomic_promotion(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    ctx.run_root(target, &["systemctl", "stop", "rustynetd.service"])
}

/// The oneshot unit whose ExecStart (`rustynet ops
/// apply-managed-dns-routing`) failed inside the katana-xnet-174 enforce
/// burst while the evidence bundle held only systemctl's own hint text.
const MANAGED_DNS_UNIT: &str = "rustynetd-managed-dns.service";

fn enforce_host(
    ctx: &LiveLabContext,
    target: &str,
    role: &str,
    node_id: &str,
    ssh_allow_cidrs: &str,
) -> Result<(), String> {
    let src_dir = LiveLabContext::remote_src_dir_for(target);
    let enforce = ctx.run_root(
        target,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
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
    );
    if let Err(enforce_err) = enforce {
        // katana-xnet-174: the managed-dns oneshot failed in this burst and
        // the bundle carried only systemctl's hint text, leaving the exact
        // failing branch unproven. Attach the failing unit's status and
        // journal tail to the stage log BEFORE the error propagates. The
        // capture is best-effort (allow-failure): it never masks or weakens
        // the enforce error — the stage still fails.
        capture_enforce_failure_evidence(ctx, target);
        return Err(enforce_err);
    }
    Ok(())
}

/// The node probes captured into the stage log after an `e2e-enforce-host`
/// failure: the managed-dns unit's status, the tail of its journal, and the
/// resolved state of the tunnel link. Diagnosis only — no check is bypassed
/// and the enforce error still fails the stage.
fn enforce_failure_evidence_probes() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "managed-dns unit status",
            vec!["systemctl", "status", MANAGED_DNS_UNIT, "--no-pager", "-l"],
        ),
        (
            "managed-dns unit journal tail",
            vec![
                "journalctl",
                "-u",
                MANAGED_DNS_UNIT,
                "-n",
                "50",
                "--no-pager",
            ],
        ),
        (
            "resolved tunnel link state",
            vec!["resolvectl", "status", TUNNEL_IFACE],
        ),
    ]
}

fn capture_enforce_failure_evidence(ctx: &LiveLabContext, target: &str) {
    capture_enforce_failure_evidence_with(
        target,
        &mut |argv| ctx.capture_root_allow_failure(target, argv),
        &mut |line| eprintln!("{line}"),
    );
}

/// Closure-driven so a unit test pins WHICH probes run, that the journal tail
/// reaches the stage log, and that an unreachable node degrades to per-probe
/// warnings instead of panicking or masking the enforce error.
fn capture_enforce_failure_evidence_with(
    target: &str,
    capture: &mut dyn FnMut(&[&str]) -> Result<String, String>,
    emit: &mut dyn FnMut(&str),
) {
    for (label, argv) in enforce_failure_evidence_probes() {
        match capture(&argv) {
            Ok(output) => emit(&format!(
                "enforce-failure evidence on {target} [{label}]:\n{output}"
            )),
            Err(err) => emit(&format!(
                "warning: enforce-failure evidence on {target} [{label}] unavailable: {err}"
            )),
        }
    }
}

fn ensure_daemon_services_ready(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
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
    )?;
    ctx.run_root(target, &["systemctl", "restart", "rustynetd.service"])?;
    ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)?;
    Ok(())
}

/// Stop the node-local assignment-refresh timer and its service unit on
/// `target` so the multi-artifact signed-bundle swap is the only writer of
/// the node's signed state for the duration of the swap.
///
/// The timer's ExecStart (`ops refresh-assignment`) self-issues and installs
/// a verifier + bundle pair signed with the NODE's own key back-to-back; this
/// test installs a pair signed with the EXIT's key. A timer run landing
/// between this test's installs leaves the two files signed by different
/// keys, which the daemon fail-closes on (traversal signature verification
/// failure -> "traversal state missing while peers are managed" ->
/// restrict_permanent). The timer is stopped BEFORE its service so the timer
/// cannot immediately re-trigger the run being stopped.
///
/// Deliberately a fence rather than a re-ordering, mirroring
/// live_linux_two_hop_test: staging would only SHRINK the inconsistent
/// window, quiescing ELIMINATES it. Unlike two_hop the daemon itself is NOT
/// stopped: the LAN-toggle assertions drive the daemon through the IPC
/// socket continuously, and enforce_host re-arms the units afterwards, so
/// the fence engages after the ensure_daemon_services_ready loop.
///
/// Idempotent: `systemctl stop` on an inactive unit succeeds as a no-op.
/// Every unit name is a fixed literal — no untrusted interpolation.
fn quiesce_node_for_bundle_swap(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    for unit in [
        "rustynetd-assignment-refresh.timer",
        "rustynetd-assignment-refresh.service",
    ] {
        ctx.run_root(target, &["systemctl", "stop", unit])?;
    }
    Ok(())
}

/// Restart the periodic assignment-refresh timer after the swap sequence has
/// completed, restoring the node to the state the stage found it in.
///
/// `systemctl start` on a running unit succeeds as a no-op, so both the
/// success path and the Drop path are safe to repeat.
fn resume_assignment_refresh_timer(ctx: &LiveLabContext, target: &str) -> Result<(), String> {
    ctx.run_root(
        target,
        &["systemctl", "start", "rustynetd-assignment-refresh.timer"],
    )
}

/// RAII guard making the quiesce/resume pair exception-safe (mirrors
/// live_linux_two_hop_test's BundleSwapFence, minus the daemon restart:
/// this test never stops the daemon).
///
/// The swap between quiesce and resume spans a long sequence of fallible SSH
/// steps, every one of which propagates with `?`. Without this guard any of
/// them would abort the stage leaving the guests' refresh timers stopped BY
/// THE TEST — confounding exactly the root-causing this fence exists to make
/// possible, and failing a later stage on
/// "rustynetd-assignment-refresh.timer is inactive" for an unrelated reason.
/// So restoration is unconditional on the error path (`drop` without
/// `release`).
struct BundleSwapFence {
    ctx: LiveLabContext,
    hosts: Vec<String>,
    released: bool,
}

impl BundleSwapFence {
    /// Stop the refresh timer + service on every host, returning the guard
    /// that will restore them. Constructed before the loop so a failure
    /// part-way through still restores the hosts already quiesced when the
    /// guard drops.
    fn quiesce(ctx: &LiveLabContext, hosts: &[&str]) -> Result<Self, String> {
        let guard = Self {
            ctx: ctx.clone(),
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            released: false,
        };
        for host in &guard.hosts {
            quiesce_node_for_bundle_swap(&guard.ctx, host)?;
        }
        Ok(guard)
    }

    /// Success-path release. `released` is set only AFTER every host is
    /// resumed; setting it first would disarm the guard before doing the
    /// work, so a failure on host 2 of 3 would leave host 3 quiesced while
    /// Drop no-ops. On an early error the guard stays armed and Drop
    /// restores every host (idempotent starts make re-resume harmless).
    fn release(mut self) -> Result<(), String> {
        for host in &self.hosts {
            resume_assignment_refresh_timer(&self.ctx, host)?;
        }
        self.released = true;
        Ok(())
    }
}

impl Drop for BundleSwapFence {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        for host in &self.hosts {
            if let Err(err) = resume_assignment_refresh_timer(&self.ctx, host) {
                eprintln!(
                    "warning: could not restart rustynetd-assignment-refresh.timer on {host} after an aborted bundle swap: {err}"
                );
            }
        }
    }
}

fn managed_dns_base_records(
    exit_node_id: &str,
    client_node_id: &str,
    blind_exit_node_id: &str,
) -> Vec<ManagedDnsRecordTemplate> {
    vec![
        ManagedDnsRecordTemplate {
            label: "exit".to_owned(),
            target_node_id: exit_node_id.to_owned(),
            ttl_secs: 300,
            aliases: vec!["gateway".to_owned()],
        },
        ManagedDnsRecordTemplate {
            label: "client".to_owned(),
            target_node_id: client_node_id.to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
        ManagedDnsRecordTemplate {
            label: "blind-exit".to_owned(),
            target_node_id: blind_exit_node_id.to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
    ]
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
            "policy reject: managed DNS scope for {} produced no policy-authorized records",
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
                return Err("config: assignment bundle node_id must not be empty".to_owned());
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
                    "config: assignment bundle peer id must not be empty: {prefix}"
                ));
            }
            peer_node_ids.push(trimmed.to_owned());
        }
    }
    peer_node_ids.sort();
    peer_node_ids.dedup();
    match node_id {
        Some(node_id) => Ok(AssignmentAuthorityScope {
            node_id,
            peer_node_ids,
        }),
        None => Err("config schema: assignment bundle is missing node_id".to_owned()),
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
        _ => "unknown".to_owned(),
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    if idx >= args.len() {
        return Err(format!("missing required argument value for {flag}"));
    }
    Ok(args[idx].clone())
}

fn print_usage() {
    println!("usage: live_linux_lan_toggle_test.sh --ssh-identity-file <path> [options]");
}

fn now_unix() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "0".to_owned(),
        |duration| duration.as_secs().to_string(),
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ssh_allow_cidrs_validation_rejects_the_qh57_wedge_shapes() {
        assert!(super::validate_ssh_allow_cidrs("").is_err());
        assert!(super::validate_ssh_allow_cidrs("   ").is_err());
        assert!(super::validate_ssh_allow_cidrs("0.0.0.0/0").is_err());
        assert!(super::validate_ssh_allow_cidrs("192.168.64.0/24,::/0").is_err());
        assert!(super::validate_ssh_allow_cidrs(super::LAN_TEST_CIDR).is_err());
        assert!(super::validate_ssh_allow_cidrs("192.168.64.0/24").is_ok());
        assert!(super::validate_ssh_allow_cidrs("192.168.64.0/24, 10.0.7.0/24").is_ok());
    }

    #[test]
    fn enforce_failure_evidence_captures_unit_status_and_journal_tail_into_stage_log() {
        // katana-xnet-174: the managed-dns oneshot failed in the enforce
        // burst and the evidence bundle held only systemctl's hint text, so
        // the exact failing branch stayed unproven. Every failure must now
        // capture the unit status, the unit journal tail, and the resolved
        // link state into the stage log.
        let mut captured: Vec<Vec<String>> = Vec::new();
        let mut emitted: Vec<String> = Vec::new();
        capture_enforce_failure_evidence_with(
            "katana-client-1",
            &mut |argv: &[&str]| {
                captured.push(argv.iter().map(ToString::to_string).collect());
                if argv[0] == "journalctl" {
                    Ok(
                        "Oct 13 02:12:40 systemd[1]: rustynetd-managed-dns.service: \
                        Main process exited, code=exited, status=1/FAILURE"
                            .to_owned(),
                    )
                } else {
                    Ok("status-body".to_owned())
                }
            },
            &mut |line: &str| emitted.push(line.to_owned()),
        );
        assert_eq!(captured.len(), 3, "all three probes must run");
        let journal_index = captured
            .iter()
            .position(|argv| argv[0] == "journalctl")
            .expect("the unit journal tail must be among the probes");
        let journal_argv = &captured[journal_index];
        assert!(
            journal_argv.contains(&"rustynetd-managed-dns.service".to_owned()),
            "the journal probe must target the managed-dns unit: {journal_argv:?}"
        );
        assert!(
            journal_argv.contains(&"--no-pager".to_owned()),
            "the journal probe must not page: {journal_argv:?}"
        );
        let status_index = captured
            .iter()
            .position(|argv| argv[0] == "systemctl" && argv[1] == "status")
            .expect("the unit status must be among the probes");
        assert!(
            captured[status_index].contains(&"rustynetd-managed-dns.service".to_owned()),
            "the status probe must target the managed-dns unit"
        );
        assert!(
            emitted.iter().any(
                |line| line.contains("enforce-failure evidence on katana-client-1")
                    && line.contains("rustynetd-managed-dns.service: Main process exited")
            ),
            "the captured journal tail must reach the stage log: {emitted:?}"
        );
    }

    #[test]
    fn enforce_failure_evidence_survives_an_unreachable_node_without_masking() {
        // A node that cannot be reached for the capture (ssh-level failure)
        // must degrade to per-probe warnings: never a panic, never a skipped
        // capture, and the enforce error still propagates unchanged.
        let mut emitted: Vec<String> = Vec::new();
        let mut capture_calls = 0usize;
        capture_enforce_failure_evidence_with(
            "katana-client-1",
            &mut |_argv: &[&str]| {
                capture_calls += 1;
                Err(format!(
                    "ssh to katana-client-1 failed (call {capture_calls})"
                ))
            },
            &mut |line: &str| emitted.push(line.to_owned()),
        );
        assert_eq!(capture_calls, 3);
        assert_eq!(emitted.len(), 3);
        assert!(
            emitted.iter().all(|line| line.contains("unavailable")
                && line.contains("ssh to katana-client-1 failed")),
            "each failed probe must be reported as unavailable: {emitted:?}"
        );
    }

    #[test]
    fn enforce_host_attaches_failure_evidence_before_propagating_the_error() {
        // Wiring pin: enforce_host must run the evidence capture on its
        // failure path BEFORE returning the enforce error, so the stage log
        // always carries the journal tail. Fails against the pre-W10 tree,
        // where enforce_host mapped the error straight through.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let start = source
            .find("\nfn enforce_host(")
            .expect("enforce_host must exist");
        let end = source[start..]
            .find("\nfn ensure_daemon_services_ready(")
            .expect("ensure_daemon_services_ready must follow enforce_host");
        let body = &source[start..start + end];
        let capture_position = body
            .find("capture_enforce_failure_evidence(")
            .unwrap_or_else(|| {
                panic!("enforce_host must capture failure evidence on its error path")
            });
        let propagate_position = body
            .find("return Err(enforce_err)")
            .expect("enforce_host must propagate the original enforce error unchanged");
        assert!(
            capture_position < propagate_position,
            "the evidence capture must run BEFORE the error propagates"
        );
    }

    #[test]
    fn enforce_failure_evidence_probes_are_fixed_safe_argvs() {
        // Every probe is a fixed literal argv against the node: no
        // interpolation of test-controlled strings into root commands.
        for (_label, argv) in enforce_failure_evidence_probes() {
            for token in &argv {
                assert!(
                    !token.is_empty()
                        && token
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric()
                                || matches!(ch, '-' | '_' | '.' | '/')),
                    "probe tokens must be fixed safe literals: {token}"
                );
            }
        }
    }

    #[test]
    fn lan_toggle_bundle_swap_fence_engages_before_first_artifact_refresh() {
        // katana-u23 root cause: this test distributed exit-signed
        // assignment/traversal pairs while every guest's 60s
        // rustynetd-assignment-refresh.timer kept self-issuing replacement
        // pairs, so the daemon read a torn (mismatched-signer) pair,
        // fail-closed with "traversal state missing while peers are managed",
        // and escalated to restrict_permanent. The fence must therefore be
        // ENGAGED before the first refresh_signed_state_artifacts call and
        // RELEASED after the last one; parsing this file's own source makes
        // the ordering claim fail loudly on any regression that reverts the
        // fence or reorders it after the first swap.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        // Bound the scan to run()'s body: the refresh helper functions below
        // run() also contain call-site text and would defeat the ordering
        // assertions.
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let fence_engage = run_body
            .find("BundleSwapFence::quiesce(")
            .expect("run() must engage the BundleSwapFence before the signed-state swap");
        let release = run_body
            .find("bundle_swap_fence.release()")
            .expect("run() must release the BundleSwapFence on the success path");
        let first_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger")
            .expect("run() must drive refresh_signed_state_artifacts");
        let last_refresh = run_body
            .rfind("refresh_signed_state_artifacts(&ctx, &logger")
            .expect("run() must drive refresh_signed_state_artifacts");
        assert!(
            fence_engage < first_refresh,
            "the bundle-swap fence must be engaged BEFORE the first \
             refresh_signed_state_artifacts call; a timer self-issue landing \
             inside the swap window tears the signed pair (katana-u23)"
        );
        assert!(
            release > last_refresh,
            "the bundle-swap fence must stay armed across the LAST \
             refresh_signed_state_artifacts call"
        );
        // The wait helpers drive refresh_signed_state_artifacts at runtime
        // (via maybe_refresh_signed_state_artifacts inside them), so every
        // wait call site in run() is an artifact refresh too and must sit
        // inside the armed window. The direct-call scan above cannot see
        // these: they live in helpers defined after run().
        for helper in ["wait_for_lan_access_state(", "wait_for_lan_probe_state("] {
            let first_wait = run_body
                .find(helper)
                .expect("run() must drive the LAN-state wait helper");
            let last_wait = run_body
                .rfind(helper)
                .expect("run() must drive the LAN-state wait helper");
            assert!(
                fence_engage < first_wait && release > last_wait,
                "every {helper} call site in run() must lie inside the \
                 armed bundle-swap window; its runtime artifact refreshes \
                 would otherwise run un-fenced (katana-u23)"
            );
        }
        let impl_end = source.find("\nmod tests {").unwrap_or(source.len());
        assert!(fence_engage < impl_end && release < impl_end);
    }

    #[test]
    fn lan_toggle_blind_exit_bundle_installed_while_daemon_is_stopped() {
        // katana-u40 root cause: run() installed the blind_exit-intent
        // signed assignment on the aux while its daemon still ran as a
        // client (the promotion via enforce_host only happened later). The
        // live daemon reconciled against the mismatched intent, burned its
        // five-reconcile budget in ~4s, restricted itself permanently and
        // failed the stage postcondition. The install must therefore happen
        // INSIDE a stopped-daemon window: stop, install, and only then let
        // enforce_host flip the role and bring the daemon back aligned.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let stop = run_body
            .find("stop_daemon_for_atomic_promotion(&ctx, &blind_exit_host)")
            .expect(
                "run() must stop the blind-exit daemon before its signed \
                 assignment is installed (atomic promotion)",
            );
        let last_install = run_body
            .rfind("install_assignment_bundle(")
            .expect("run() must install the signed assignment bundles");
        let last_env_install = run_body
            .rfind("install_assignment_refresh_env(&ctx, &blind_exit_host")
            .expect("run() must install the blind-exit node-local refresh env");
        let first_enforce = run_body
            .find("enforce_host(&ctx, &exit_host")
            .expect("run() must enforce the host roles");
        assert!(
            stop < last_install,
            "the blind-exit daemon must be STOPPED before the last \
             install_assignment_bundle call; a live still-client daemon \
             reconciling a blind_exit-intent bundle restricts itself \
             permanently (katana-u40)"
        );
        assert!(
            stop < last_env_install,
            "the node-local refresh env must be installed inside the \
             stopped-daemon window so the daemon's first refresh already \
             agrees with the installed assignment"
        );
        assert!(
            last_install < first_enforce,
            "the blind-exit assignment must be installed before enforce_host \
             flips the role, so the daemon first boots already aligned"
        );
    }

    #[test]
    fn lan_toggle_client_signs_its_own_assignment_while_the_coupling_runs() {
        // katana-xnet-149 root cause: `ops apply-lan-access-coupling` makes the
        // node re-issue its assignment with the NODE-LOCAL signing secret. With
        // the exit's verifier key on the client the refresh service refuses to
        // re-issue (assignment.pub belongs to another authority), so the node
        // under test must be its own assignment authority while the coupling
        // runs, and the lab's usual exit-signed pair must be restored before
        // the stage ends. Parsing this file's own source makes the ordering
        // claim fail loudly on any regression.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];

        let config = run_body
            .find("let signed_state_refresh = SignedStateRefreshConfig {")
            .expect("run() must build the main signed-state refresh config");
        let self_signed = config
            + run_body[config..]
                .find("client_self_signed: true")
                .expect("the main refresh config must make the client sign its own assignment");
        let first_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger")
            .expect("run() must drive refresh_signed_state_artifacts");
        let first_coupling = run_body
            .find("apply_lan_access(")
            .expect("run() must drive the LAN coupling");
        assert!(
            self_signed < first_refresh && first_refresh < first_coupling,
            "the client must be self-signed (via the second refresh) before the first \
             LAN coupling runs"
        );
        // The self-signed swap is the SECOND refresh: the first refresh keeps
        // the client exit-signed for the negative control that precedes it.
        let swap_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;")
            .expect(
                "run() must swap the client to its own authority only \
                 after the exit-signed negative control",
            );
        assert!(
            first_refresh < swap_refresh && swap_refresh < first_coupling,
            "the self-signed swap must sit between the exit-signed first refresh \
             and the first LAN coupling"
        );

        let last_coupling = run_body
            .rfind("apply_lan_access(")
            .expect("run() must drive the LAN coupling");
        // rfind: the exit-signed FIRST refresh's config variant above also
        // spells client_self_signed: false; the restore config is the LAST
        // such definition.
        let restore_config = run_body
            .rfind("client_self_signed: false")
            .expect("run() must build a restore config that returns the client to the exit");
        let restore_refresh = run_body
            .rfind("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_restore)")
            .expect("run() must refresh with the restore config");
        let release = run_body
            .find("bundle_swap_fence.release()")
            .expect("run() must release the fence on the success path");
        assert!(
            last_coupling < restore_config && restore_config < restore_refresh,
            "the exit-signed client pair is restored only after the last client coupling"
        );
        assert!(
            restore_refresh < release,
            "the restore must happen inside the armed bundle-swap fence"
        );

        // The helper issues on the CLIENT (its own signing secret) and installs
        // the client's OWN verifier key with the client's bundle.
        let helper_start = source
            .find("\nfn refresh_assignment_bundles(")
            .expect("refresh_assignment_bundles must exist");
        let helper_end = source[helper_start..]
            .find("\nfn refresh_traversal_bundles(")
            .map(|offset| helper_start + offset)
            .expect("refresh_assignment_bundles must end before the traversal refresh");
        let helper = &source[helper_start..helper_end];
        assert!(helper.contains("if config.client_self_signed {"));
        assert!(
            helper.matches("issue_assignment_bundles_from_env(").count() >= 2,
            "the self-signed branch must issue a second set on the client host"
        );
        assert!(
            helper.contains("config.client_assign_pub_local"),
            "the client's own verifier key must be captured and installed with its bundle"
        );
    }

    #[test]
    fn lan_toggle_client_trust_anchor_swaps_install_both_halves_in_one_remote_shell() {
        // The torn-swap failure mode: the client's 60s node-local refresh
        // timer races a pub-then-bundle install done as separate root
        // commands, the daemon reconciles a NEW verifier against the OLD
        // bundle, fails signature verification and burns its reconcile budget
        // into a permanent restriction. The client-side swap must therefore
        // install both halves (and remove the stale watermark) in ONE remote
        // shell. Source pins make any split back into separate commands fail
        // loudly.
        let source = include_str!("live_linux_lan_toggle_test.rs");

        // The atomic helper itself.
        let helper_start = source
            .find("const ASSIGNMENT_PUB_INSTALL_ARGS")
            .expect("atomic install argv consts must exist");
        let helper_end = source[helper_start..]
            .find("\nfn remote_file_sha256(")
            .map(|offset| helper_start + offset)
            .expect("the atomic install helper must end before remote_file_sha256");
        let helper = &source[helper_start..helper_end];
        assert!(helper.contains("const ASSIGNMENT_BUNDLE_INSTALL_ARGS"));
        assert!(helper.contains("const ASSIGNMENT_SWAP_CLEANUP_ARGS"));
        assert_eq!(
            helper.matches("ctx.run_root(").count(),
            1,
            "the atomic helper must issue exactly ONE remote root command \
             (sh -c); a second command re-opens the torn window"
        );
        assert!(
            helper.contains("script.push_str(\" && \")"),
            "the remote steps must be chained with && so a failed install \
             aborts the rest of the swap"
        );
        assert!(
            helper.contains("shell_single_quote("),
            "every remote argv element must be single-quoted before it lands \
             in the sh -c script"
        );
        assert!(
            !helper.contains("install_assignment_bundle("),
            "the atomic helper must not recurse into the plain installer"
        );
        let first_scp = helper
            .find("ctx.scp_to(")
            .expect("the atomic helper must ship both halves first");
        let shell = helper
            .find("ctx.run_root(")
            .expect("the atomic helper must end in exactly one remote shell");
        assert!(
            first_scp < shell,
            "both halves must be shipped to /tmp BEFORE the single swap shell runs"
        );

        // Only the CLIENT install in refresh_assignment_bundles uses it.
        let helper_refresh_start = source
            .find("\nfn refresh_assignment_bundles(")
            .expect("refresh_assignment_bundles must exist");
        let helper_refresh_end = source[helper_refresh_start..]
            .find("\nfn refresh_traversal_bundles(")
            .map(|offset| helper_refresh_start + offset)
            .expect("refresh_assignment_bundles must end before the traversal refresh");
        let refresh_bundles = &source[helper_refresh_start..helper_refresh_end];
        assert_eq!(
            refresh_bundles
                .matches("install_assignment_bundle_atomically(")
                .count(),
            1,
            "exactly the client's trust-anchor swap must be atomic"
        );
        assert_eq!(
            refresh_bundles
                .matches("install_assignment_bundle(")
                .count(),
            2,
            "the exit and blind-exit installs keep their plain form; only the \
             client's pub half actually changes mid-run"
        );
    }

    #[test]
    fn lan_toggle_negative_control_runs_on_the_exit_signed_client_before_the_swap() {
        // Review criterion C, proven not assumed: while the client still
        // holds the EXIT-signed pair (it is NOT its own assignment
        // authority), the LAN-ON coupling must be REFUSED with the
        // kept-bundle text, must leave the installed bundle byte-identical,
        // and must keep the daemon out of restricted-safe mode. The control
        // must run BEFORE the self-signed swap (otherwise it proves nothing)
        // and the coupling it attempted must have its env rewrite restored
        // before the swap.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let fence = run_body
            .find("BundleSwapFence::quiesce(")
            .expect("run() must engage the bundle-swap fence");
        let exit_variant = run_body
            .find("let signed_state_refresh_exit_signed = SignedStateRefreshConfig {")
            .expect("run() must build an explicit exit-signed refresh variant");
        let exit_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_exit_signed)?;")
            .expect("run() must first refresh the client EXIT-SIGNED");
        let control = run_body
            .find("run_lan_coupling_negative_control(&ctx, &logger, platform, &client_host)?;")
            .expect("run() must run the negative control on the exit-signed client");
        let env_restore = run_body
            .rfind("install_assignment_refresh_env(&ctx, &client_host, &client_refresh_local)?;")
            .expect("run() must restore the client's refresh env after the control");
        let main_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;")
            .expect("run() must swap the client self-signed only after the control");
        let first_coupling = run_body
            .find("apply_lan_access(")
            .expect("run() must drive the LAN coupling");
        assert!(
            fence < exit_variant
                && exit_variant < exit_refresh
                && exit_refresh < control
                && control < env_restore
                && env_restore < main_refresh
                && main_refresh < first_coupling,
            "ordering: fence -> exit-signed refresh -> negative control -> env \
             restore -> self-signed swap -> first coupling"
        );

        // The control function itself must compare bundle digests and demand
        // a healthy daemon.
        let control_start = source
            .find("fn run_lan_coupling_negative_control(")
            .expect("the negative control must exist");
        let control_end = source[control_start..]
            .find("\nfn log_reconcile_failures_after_trust_anchor_swap(")
            .map(|offset| control_start + offset)
            .expect("the negative control must end before the reconcile logger");
        let control_fn = &source[control_start..control_end];
        assert_eq!(
            control_fn.matches("remote_file_sha256(").count(),
            2,
            "the control must digest the installed bundle before AND after the \
             refused coupling (via remote_file_sha256)"
        );
        let sha_start = source
            .find("fn remote_file_sha256(")
            .expect("the digest helper must exist");
        let sha_end = source[sha_start..]
            .find("\nconst KEPT_BUNDLE_ERROR_MARKER")
            .map(|offset| sha_start + offset)
            .expect("the digest helper must end before the kept-bundle marker");
        assert!(
            source[sha_start..sha_end].contains("sha256sum"),
            "the digest helper must actually run sha256sum on the guest"
        );
        assert!(
            control_fn.contains("bundle_sha_before != bundle_sha_after"),
            "the control must fail when the refused coupling changed the bundle"
        );
        assert!(
            control_fn.contains("restricted_safe_mode=false"),
            "the control must demand the daemon stay OUT of restricted-safe mode"
        );

        // The expectation helper must require the kept-bundle marker text.
        let expect_start = source
            .find("fn apply_lan_access_expect_kept_bundle(")
            .expect("the kept-bundle expectation helper must exist");
        let expect_end = source[expect_start..]
            .find("\nfn run_lan_coupling_negative_control(")
            .map(|offset| expect_start + offset)
            .expect("the expectation helper must end before the negative control");
        let expect_fn = &source[expect_start..expect_end];
        assert!(expect_fn.contains("KEPT_BUNDLE_ERROR_MARKER"));
        assert!(
            expect_fn.contains("output.status.success()"),
            "a SUCCESSFUL coupling on an external-authority node is the \
             failure this control exists to catch"
        );
    }

    #[test]
    fn lan_toggle_cleanup_restores_the_exit_signed_client_pair_after_a_mid_stage_failure() {
        // A failure between the self-signed swap and the restore refresh used
        // to leave the guest client as its own assignment authority (own
        // verifier key + node-local signing secret): exactly the state the
        // post-stage stages cannot handle. The cleanup Drop must put the
        // exit-signed pair back best-effort, driven by a flag that is armed
        // only while the client really is self-signed.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let struct_start = source
            .find("struct LanToggleCleanup {")
            .expect("LanToggleCleanup must exist");
        let drop_start = source
            .find("impl Drop for LanToggleCleanup {")
            .expect("LanToggleCleanup must have a Drop impl");
        let struct_def = &source[struct_start..drop_start];
        assert!(struct_def.contains("client_host: String"));
        assert!(struct_def.contains("client_self_signed: bool"));
        assert!(struct_def.contains("exit_assign_pub_local: Option<PathBuf>"));
        assert!(struct_def.contains("client_exit_assignment_local: Option<PathBuf>"));

        let drop_end = source[drop_start..]
            .find("\nfn apply_lan_access(")
            .map(|offset| drop_start + offset)
            .expect("the Drop impl must end before apply_lan_access");
        let drop_body = &source[drop_start..drop_end];
        assert!(drop_body.contains("if self.client_self_signed {"));
        assert!(
            drop_body.contains("install_assignment_bundle_atomically("),
            "the restore must be atomic like the swap itself"
        );
        assert!(
            drop_body.contains("self.client_self_signed = false;"),
            "the Drop must disarm the flag so the restore never double-runs"
        );

        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        assert!(
            run_body.contains("assignment-client-exit-signed"),
            "run() must snapshot the client's exit-signed bundle for the restore"
        );
        let swap_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;")
            .expect("run() must swap the client self-signed");
        let armed = run_body
            .find("cleanup.client_self_signed = true;")
            .expect("run() must arm the cleanup flag right after the swap");
        let restore_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_restore)?;")
            .expect("run() must restore the exit-signed pair on the success path");
        let disarmed = run_body
            .rfind("cleanup.client_self_signed = false;")
            .expect("run() must disarm the cleanup flag after the restore");
        assert!(
            swap_refresh < armed && armed < restore_refresh && restore_refresh < disarmed,
            "the cleanup flag must be armed exactly while the client is self-signed"
        );
    }

    #[test]
    fn lan_toggle_logs_client_reconcile_failures_after_each_trust_anchor_swap() {
        // katana-u23/u40 both showed up as the daemon burning its
        // reconcile_failures budget during a trust-anchor swap. The swap must
        // log the client's reconcile_failures counter right after BOTH
        // directions (exit-signed -> self-signed and back) so a future live
        // run's log exposes a budget burn immediately. Diagnostics only: the
        // logger must never fail the stage.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let fn_start = source
            .find("fn log_reconcile_failures_after_trust_anchor_swap(")
            .expect("the reconcile logger must exist");
        let fn_end = source[fn_start..]
            .find("\nfn install_assignment_refresh_env(")
            .map(|offset| fn_start + offset)
            .expect("the reconcile logger must end before install_assignment_refresh_env");
        let helper = &source[fn_start..fn_end];
        assert!(
            helper.contains("capture_root_allow_failure"),
            "the logger must tolerate a dead daemon: it is diagnostics, not an assertion"
        );
        assert!(helper.contains("reconcile_failures"));
        assert!(
            !helper.contains("-> Result<"),
            "the logger must return () so it can never fail the stage"
        );

        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let swap_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh)?;")
            .expect("run() must swap the client self-signed");
        let log_after_swap = run_body
            .find("exit-signed -> self-signed swap")
            .expect("run() must log reconcile state after the self-signed swap");
        let restore_refresh = run_body
            .find("refresh_signed_state_artifacts(&ctx, &logger, &signed_state_refresh_restore)?;")
            .expect("run() must restore the exit-signed pair");
        let log_after_restore = run_body
            .rfind("self-signed -> exit-signed restore")
            .expect("run() must log reconcile state after the restore");
        assert!(
            swap_refresh < log_after_swap
                && log_after_swap < restore_refresh
                && restore_refresh < log_after_restore,
            "reconcile logging must bracket BOTH trust-anchor swaps"
        );
    }

    #[test]
    fn lan_toggle_fence_stops_timer_before_service_and_restores_it() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let impl_end = source.find("\nmod tests {").unwrap_or(source.len());
        let impl_text = &source[..impl_end];
        // The timer is stopped BEFORE its service so the timer cannot
        // immediately re-trigger the run being stopped.
        let timer_needle = "\"rustynetd-assignment-refresh.timer\"";
        let service_needle = "\"rustynetd-assignment-refresh.service\"";
        let timer_pos = impl_text
            .find(timer_needle)
            .expect("quiesce must name the assignment-refresh timer unit");
        let service_pos = impl_text
            .find(service_needle)
            .expect("quiesce must also stop the assignment-refresh service unit");
        assert!(
            timer_pos < service_pos,
            "the timer must be stopped before the service unit"
        );
        // Both quiesce (systemctl stop) and restore (systemctl start) paths
        // exist, and the Drop guard is armed via `released`.
        assert!(impl_text.contains("\"systemctl\", \"stop\", unit"));
        assert!(
            impl_text
                .contains("&[\"systemctl\", \"start\", \"rustynetd-assignment-refresh.timer\"]")
        );
        assert!(
            impl_text.contains("fn drop(&mut self)") && impl_text.contains("if self.released"),
            "the fence must restore the timer unconditionally via an armed Drop guard"
        );
        // The daemon itself is deliberately NOT stopped here (unlike two_hop):
        // banning the daemon stop keeps the fence from breaking the IPC-driven
        // toggle assertions.
        let quiesce_start = impl_text
            .find("fn quiesce_node_for_bundle_swap(")
            .expect("quiesce helper must exist");
        let quiesce_end = impl_text[quiesce_start..]
            .find("\n}\n")
            .map(|offset| quiesce_start + offset)
            .expect("quiesce helper must terminate");
        assert!(
            !impl_text[quiesce_start..quiesce_end].contains("rustynetd.service"),
            "the lan-toggle fence must NOT stop rustynetd.service; the toggle \
             assertions drive the daemon through its IPC socket"
        );
    }

    #[test]
    fn ssh_allow_cidrs_has_no_baked_in_default() {
        // A literal default here is exactly what wedged the client in QH-57:
        // the needle is assembled at runtime so this test's own source cannot
        // satisfy the negative assertion.
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let banned = format!("ssh_allow_cidrs = String::from(\"{}\")", "192.168.18.0/24");
        assert!(
            !source.contains(banned.as_str()),
            "the ssh-allow-cidrs default must stay removed (QH-57)"
        );
        let required = format!("let mut ssh_allow_cidrs = String::{}();", "new");
        assert!(source.contains(required.as_str()));
        // The needles above pin ONE construction spelling (`String::from`) and
        // one init shape. `push_str`, `format!`, a const, or any other
        // assembly reintroduces the QH-57 wedge while both stay green. Ban the
        // CIDR VALUE itself in code. Bound the scan to the implementation
        // region (everything before the unit-test module): this test's own
        // runtime-assembled needle legitimately names the value, and comment
        // lines are exempt because the rationale comment names it too.
        let cidr = ["192.168.", "18.0/24"].concat();
        let impl_end = source.find("\nmod tests {").unwrap_or(source.len());
        for (index, line) in source[..impl_end].lines().enumerate() {
            let trimmed = line.trim_start();
            assert!(
                trimmed.starts_with("//") || !line.contains(cidr.as_str()),
                "line {} embeds the QH-57 wedge CIDR {cidr} in implementation code; \
                 ssh-allow-cidrs must stay operator-supplied with no baked-in default",
                index + 1
            );
        }
        // The whole-value ban above is defeated by SPLITTING the constant:
        // two string pieces assembled through format!/push_str/concat
        // reintroduce the wedge while no single line carries the full value
        // (proven by mutation). Ban the natural split fragments too — the
        // distinctive `18.0` octet boundary and the bare prefix. Splits into
        // three or more innocuous pieces remain a residual of ANY value-grep
        // pin; the operator-supplied requirement itself is separately enforced
        // at runtime by validate_ssh_allow_cidrs rejecting empty input.
        let fragments = ["18.0/24", "192.168.18.0"];
        for fragment in fragments {
            for (index, line) in source[..impl_end].lines().enumerate() {
                let trimmed = line.trim_start();
                assert!(
                    trimmed.starts_with("//") || !line.contains(fragment),
                    "line {} embeds QH-57 wedge fragment {fragment} in \
                     implementation code; a split-constant assembly reintroduces \
                     the baked-in ssh default this test bans",
                    index + 1
                );
            }
        }
        // A value-grep cannot follow DATAFLOW: pieces cut BETWEEN the pinned
        // fragments ("192.168.18" + ".0/24" assembles the wedge with no banned
        // fragment on any line; proven green by mutation) defeat every value
        // pin above. Pin the variable's SOURCES instead: ssh_allow_cidrs may
        // only ever be written by the empty init or the operator-supplied
        // --ssh-allow-cidrs value, so no assembly anywhere can bake a default
        // in regardless of how it is spelled or split.
        for (index, line) in source[..impl_end].lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !(line.contains("ssh_allow_cidrs")
                    && (line.contains("push_str")
                        || line.contains("&mut ssh_allow_cidrs")
                        || line.contains("insert(")
                        || line.contains("extend(")
                        || line.contains("write!("))),
                "line {} mutates ssh_allow_cidrs through an assembly spelling; \
                 the variable may only ever hold the operator-supplied \
                 --ssh-allow-cidrs value (QH-57)",
                index + 1
            );
            if line.contains("ssh_allow_cidrs =") {
                assert!(
                    line.contains("String::new()") || line.contains("required_value(&args"),
                    "line {} assigns ssh_allow_cidrs from an unsanctioned source; \
                     only the String::new() init and the required_value(...) \
                     operator argument may write it (QH-57)",
                    index + 1
                );
            }
        }
    }

    use super::{
        AssignmentAuthorityScope, LiveLabPlatform, ManagedDnsRecordTemplate,
        capture_enforce_failure_evidence_with, daemon_socket_path, enforce_failure_evidence_probes,
        is_macos_utun_iface_name, killswitch_drop_table_present, killswitch_dump_argv,
        killswitch_enforcement_present, lan_probe_argv, macos_killswitch_anchor_present,
        managed_dns_base_records, managed_dns_records_manifest_for_scope,
        parse_assignment_authority_scope, route_to_target_argv, route_to_target_uses_tunnel,
        windows_killswitch_present,
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
                node_id: "client-1".to_owned(),
                peer_node_ids: vec!["client-3".to_owned(), "exit-1".to_owned()],
            }
        );
    }

    #[test]
    fn managed_dns_records_manifest_filters_unauthorized_targets() {
        let mut records = managed_dns_base_records("exit-1", "client-1", "client-3");
        records.push(ManagedDnsRecordTemplate {
            label: "blocked".to_owned(),
            target_node_id: "client-9".to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        });
        let scope = AssignmentAuthorityScope {
            node_id: "client-1".to_owned(),
            peer_node_ids: vec!["exit-1".to_owned()],
        };
        let manifest = managed_dns_records_manifest_for_scope(&records, &scope)
            .expect("manifest should be filtered to authorized records");
        assert!(manifest.contains("target_node_id=client-1"));
        assert!(manifest.contains("target_node_id=exit-1"));
        assert!(!manifest.contains("target_node_id=client-3"));
        assert!(!manifest.contains("target_node_id=client-9"));
    }

    #[test]
    fn route_via_tunnel_detected_when_dev_rustynet0_present() {
        // The LAN-ON positive control shape (Linux): route resolves over the
        // tunnel. Behaviour is byte-identical to the pre-Wave-2 single-OS check.
        let lan_on = "192.168.1.1 dev rustynet0 src 100.64.0.2 uid 0 \n    cache";
        assert!(route_to_target_uses_tunnel(LiveLabPlatform::Linux, lan_on));
    }

    #[test]
    fn route_withdrawn_when_target_not_via_tunnel() {
        // LAN-OFF (Linux): the advertised LAN route is withdrawn, so the target
        // either resolves over a non-tunnel dev or does not resolve at all.
        let via_lan_iface = "192.168.1.1 dev eth0 src 192.168.18.65 uid 0 \n    cache";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Linux,
            via_lan_iface
        ));

        let unreachable = "RTNETLINK answers: Network is unreachable";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Linux,
            unreachable
        ));

        // Defense in depth: an empty/garbage capture is "not via tunnel".
        assert!(!route_to_target_uses_tunnel(LiveLabPlatform::Linux, ""));
        assert!(!route_to_target_uses_tunnel(LiveLabPlatform::Linux, "dev"));
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Linux,
            "rustynet0"
        ));
    }

    #[test]
    fn route_dev_match_is_not_a_substring_false_positive() {
        // `rustynet0x` / `rustynet01` must NOT count as the tunnel device, and
        // a bare mention of the iface name outside a `dev <iface>` pair must not
        // either.
        let other_iface = "192.168.1.1 dev rustynet0x src 100.64.0.2 uid 0";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Linux,
            other_iface
        ));
        let mentioned_only = "192.168.1.1 via rustynet0 dev eth0 src 192.168.18.65";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Linux,
            mentioned_only
        ));
    }

    #[test]
    fn macos_route_via_tunnel_detected_for_utun_interface() {
        // Real `route -n get <ip>` block shape on macOS: an `interface: utunN`
        // line means the LAN route resolves over the dynamic utun tunnel.
        let lan_on = "   route to: 192.168.1.1\ndestination: 192.168.1.1\n       gateway: 100.64.0.1\n     interface: utun6\n         flags: <UP,GATEWAY,DONE>\n";
        assert!(route_to_target_uses_tunnel(LiveLabPlatform::MacOs, lan_on));
    }

    #[test]
    fn macos_route_withdrawn_when_interface_is_not_utun() {
        // LAN-OFF on macOS: route resolves over the physical NIC (en0) or not at
        // all. `utun` with no digits, a confusable name, and empty input all fail
        // closed to "not via tunnel".
        let via_en0 = "   route to: 192.168.1.1\ndestination: 192.168.1.1\n       gateway: 192.168.1.254\n     interface: en0\n";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::MacOs,
            via_en0
        ));

        let no_route = "route: writing to routing socket: not in table\n";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::MacOs,
            no_route
        ));

        let bare_utun = "     interface: utun\n";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::MacOs,
            bare_utun
        ));
        let confusable = "     interface: utunX\n";
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::MacOs,
            confusable
        ));
        assert!(!route_to_target_uses_tunnel(LiveLabPlatform::MacOs, ""));
    }

    #[test]
    fn macos_utun_iface_name_matcher_requires_numeric_suffix() {
        assert!(is_macos_utun_iface_name("utun0"));
        assert!(is_macos_utun_iface_name("utun9"));
        assert!(is_macos_utun_iface_name("utun123"));
        assert!(!is_macos_utun_iface_name("utun"));
        assert!(!is_macos_utun_iface_name("utunX"));
        assert!(!is_macos_utun_iface_name("xutun9"));
        assert!(!is_macos_utun_iface_name("en0"));
        assert!(!is_macos_utun_iface_name(""));
    }

    #[test]
    fn windows_route_via_tunnel_detected_when_get_netroute_row_present() {
        // `Get-NetRoute -InterfaceAlias rustynet0 ... -HideTableHeaders` already
        // filtered to the tunnel adapter: a returned data row means the route
        // still resolves over the tunnel.
        let row = "192.168.1.1/32        0.0.0.0                rustynet0            256\n";
        assert!(route_to_target_uses_tunnel(LiveLabPlatform::Windows, row));
    }

    #[test]
    fn windows_route_withdrawn_when_get_netroute_returns_no_rows() {
        // LAN-OFF on Windows: the alias-filtered query returns zero rows
        // (empty/whitespace stdout) when the tunnel route is withdrawn.
        assert!(!route_to_target_uses_tunnel(LiveLabPlatform::Windows, ""));
        assert!(!route_to_target_uses_tunnel(
            LiveLabPlatform::Windows,
            "   \n  \n"
        ));
    }

    #[test]
    fn lan_probe_argv_is_per_os() {
        assert_eq!(
            lan_probe_argv(LiveLabPlatform::Linux),
            vec!["ping", "-c", "1", "-W", "1", "192.168.1.1"]
        );
        assert_eq!(
            lan_probe_argv(LiveLabPlatform::MacOs),
            vec!["ping", "-c", "1", "-t", "2", "192.168.1.1"]
        );
        let windows = lan_probe_argv(LiveLabPlatform::Windows);
        assert_eq!(windows[0], "powershell");
        assert!(windows.iter().any(|arg| arg.contains("Test-Connection")));
    }

    #[test]
    fn route_to_target_argv_is_per_os() {
        assert_eq!(
            route_to_target_argv(LiveLabPlatform::Linux),
            vec!["ip", "-4", "route", "get", "192.168.1.1"]
        );
        assert_eq!(
            route_to_target_argv(LiveLabPlatform::MacOs),
            vec!["route", "-n", "get", "192.168.1.1"]
        );
        let windows = route_to_target_argv(LiveLabPlatform::Windows);
        assert_eq!(windows[0], "powershell");
        assert!(windows.iter().any(|arg| arg.contains("Get-NetRoute")));
        assert!(windows.iter().any(|arg| arg.contains("rustynet0")));
    }

    #[test]
    fn killswitch_dump_argv_is_per_os() {
        assert_eq!(
            killswitch_dump_argv(LiveLabPlatform::Linux),
            vec!["nft", "list", "ruleset"]
        );
        assert_eq!(
            killswitch_dump_argv(LiveLabPlatform::MacOs),
            vec!["pfctl", "-s", "Anchors"]
        );
        let windows = killswitch_dump_argv(LiveLabPlatform::Windows);
        assert_eq!(windows[0], "powershell");
        assert!(
            windows
                .iter()
                .any(|arg| arg.contains("Get-NetFirewallProfile"))
        );
        assert!(windows.iter().any(|arg| arg.contains("RustyNetKS-")));
    }

    #[test]
    fn daemon_socket_path_is_per_os_and_none_for_windows() {
        assert_eq!(
            daemon_socket_path(LiveLabPlatform::Linux),
            Some("/run/rustynet/rustynetd.sock")
        );
        assert_eq!(
            daemon_socket_path(LiveLabPlatform::MacOs),
            Some("/private/var/run/rustynet/rustynetd.sock")
        );
        // Windows daemon IPC is a named pipe, not a Unix socket.
        assert_eq!(daemon_socket_path(LiveLabPlatform::Windows), None);
    }

    #[test]
    fn macos_killswitch_anchor_present_detects_killswitch_and_blind_exit() {
        // `pfctl -s Anchors` lists the generation-numbered killswitch anchor.
        let anchors = "com.apple/250.AppleFirewall\ncom.apple/rustynet_g7\n";
        assert!(macos_killswitch_anchor_present(anchors));

        // The fixed blind_exit anchor is also positive enforcement evidence.
        let blind_exit = "com.apple/250.AppleFirewall\ncom.rustynet/blind_exit\n";
        assert!(macos_killswitch_anchor_present(blind_exit));

        // Dumping the anchor rules instead yields the terminal block-all rule.
        let rules = "set block-policy drop\nblock drop out quick all\n";
        assert!(macos_killswitch_anchor_present(rules));
    }

    #[test]
    fn macos_killswitch_anchor_absent_yields_no_enforcement_evidence() {
        assert!(!macos_killswitch_anchor_present(""));
        // Unrelated anchors only.
        let unrelated = "com.apple/250.AppleFirewall\ncom.apple/250.PassiveFTP\n";
        assert!(!macos_killswitch_anchor_present(unrelated));
        // A confusable / non-numeric generation suffix must NOT match.
        let confusable = "com.apple/rustynet_gX\ncom.apple/rustynet_g\n";
        assert!(!macos_killswitch_anchor_present(confusable));
    }

    #[test]
    fn windows_killswitch_present_detects_block_outbound_and_rule() {
        // `Get-NetFirewallProfile | Format-List Name,DefaultOutboundAction`.
        let block_profile = "Name                  : Domain\nDefaultOutboundAction : Block\n";
        assert!(windows_killswitch_present(block_profile));

        // A named RustyNetKS- allow rule is also positive evidence.
        let rule_row = "RustyNetKS-AllowLoopback\nRustyNetKS-AllowEgress\n";
        assert!(windows_killswitch_present(rule_row));
    }

    #[test]
    fn windows_killswitch_absent_yields_no_enforcement_evidence() {
        assert!(!windows_killswitch_present(""));
        // Default outbound is Allow (not enforced) — must NOT match.
        let allow_profile = "Name                  : Public\nDefaultOutboundAction : Allow\n";
        assert!(!windows_killswitch_present(allow_profile));
        // NotConfigured is also not enforcement evidence.
        let not_configured =
            "Name                  : Private\nDefaultOutboundAction : NotConfigured\n";
        assert!(!windows_killswitch_present(not_configured));
        // Unrelated firewall rule names must not match.
        let other_rule = "Core Networking - DNS (UDP-Out)\n";
        assert!(!windows_killswitch_present(other_rule));
    }

    #[test]
    fn killswitch_enforcement_present_dispatches_per_os() {
        // Each OS's positive sample is recognized only through its own branch.
        assert!(killswitch_enforcement_present(
            LiveLabPlatform::Linux,
            "table inet rustynet_g3 {\n}\n"
        ));
        assert!(killswitch_enforcement_present(
            LiveLabPlatform::MacOs,
            "com.apple/rustynet_g3\n"
        ));
        assert!(killswitch_enforcement_present(
            LiveLabPlatform::Windows,
            "DefaultOutboundAction : Block\n"
        ));
        // Cross-OS confusion guard: a macOS anchor dump is not Linux evidence.
        assert!(!killswitch_enforcement_present(
            LiveLabPlatform::Linux,
            "com.apple/rustynet_g3\n"
        ));
    }

    #[test]
    fn killswitch_table_present_for_bare_and_rotated_generations() {
        let bare = "table inet rustynet {\n  chain killswitch {\n  }\n}\n";
        assert!(killswitch_drop_table_present(bare));

        let rotated = "table inet rustynet_g7 {\n  chain killswitch {\n  }\n}\n";
        assert!(killswitch_drop_table_present(rotated));

        // Leading whitespace on the table line must still match.
        let indented = "  table inet rustynet_g12 {\n  }\n";
        assert!(killswitch_drop_table_present(indented));
    }

    #[test]
    fn killswitch_table_absent_yields_no_enforcement_evidence() {
        // Empty / unrelated ruleset: no killswitch table.
        assert!(!killswitch_drop_table_present(""));
        let unrelated = "table ip nat {\n  chain postrouting {\n  }\n}\n";
        assert!(!killswitch_drop_table_present(unrelated));

        // Wrong family for the canonical name must not match.
        let wrong_family = "table ip rustynet {\n}\n";
        assert!(!killswitch_drop_table_present(wrong_family));

        // A confusable name (prefix-only, or a non-numeric/empty generation
        // suffix) must NOT be treated as the canonical killswitch table.
        let confusable_prefix = "table inet rustynetwork {\n}\n";
        assert!(!killswitch_drop_table_present(confusable_prefix));
        let confusable_suffix = "table inet rustynet_gabc {\n}\n";
        assert!(!killswitch_drop_table_present(confusable_suffix));
        let empty_generation = "table inet rustynet_g {\n}\n";
        assert!(!killswitch_drop_table_present(empty_generation));
    }

    // The materialized DNS signing passphrase is plaintext secret material on
    // the guest: it must be created under /run (tmpfs, gone on reboot), never
    // /tmp (a SIGKILL before the cleanup would leave a 0600 root-owned
    // plaintext passphrase surviving the reboot).
    #[test]
    fn dns_passphrase_materializes_under_run_not_tmp() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        assert!(
            source.contains("\"mktemp\", \"/run/rn-lan-toggle-dns-passphrase.XXXXXX\""),
            "the passphrase mktemp must target /run:\n{source}"
        );
        assert!(
            !source.contains("rn-lan-toggle-dns-passphrase.XXXXXX\", \"/tmp"),
            "no /tmp spelling of the passphrase path may remain"
        );
        let impl_end = source.find("\nmod tests {").unwrap_or(source.len());
        for (index, line) in source[..impl_end].lines().enumerate() {
            assert!(
                !line.contains("/tmp/rn-lan-toggle-dns-passphrase"),
                "line {} writes the DNS passphrase under /tmp; use /run (tmpfs)",
                index + 1
            );
        }
    }

    // ── pre-toggle refresh-env snapshot / restore ─────────────────────────

    fn snapshot(host: &str, env: Option<&str>, timer: Option<&str>) -> super::RefreshEnvSnapshot {
        super::RefreshEnvSnapshot {
            host: host.to_owned(),
            env_body: env.map(str::to_owned),
            timer_is_active_raw: timer.map(str::to_owned),
        }
    }

    /// A participant that had a refresh env before the toggle gets the
    /// captured bytes reinstalled on restore — never removal.
    #[test]
    fn restore_action_reinstalls_the_captured_env() {
        let snap = snapshot(
            "exit-1",
            Some("RUSTYNET_ASSIGNMENT_NODES=\"fleet\"\n"),
            Some("active"),
        );
        assert_eq!(
            super::refresh_env_restore_action(&snap),
            super::RefreshEnvRestoreAction::Reinstall(
                "RUSTYNET_ASSIGNMENT_NODES=\"fleet\"\n".to_owned()
            )
        );
    }

    /// katana-xnet-169 kill (mutant: treat a missing as-found env as a
    /// no-op restore): the toggle's narrowed env must be REMOVED when no
    /// env existed before the toggle, on every path — otherwise the stage
    /// leaves the poison in place and the next full-fleet pair swap trips
    /// the daemon's QH-04 fail-closed invariant.
    #[test]
    fn restore_env_action_removes_env_when_none_captured() {
        assert_eq!(
            super::refresh_env_restore_action(&snapshot("client-1", None, Some("inactive"))),
            super::RefreshEnvRestoreAction::Remove
        );
        // An empty/whitespace capture is indistinguishable from absent and
        // must also restore to removal, not to a zero-byte env.
        assert_eq!(
            super::refresh_env_restore_action(&snapshot("aux-1", Some("   \n"), None)),
            super::RefreshEnvRestoreAction::Remove
        );
    }

    /// The disarm argv targets the refresh TIMER unit exactly — a mutant
    /// that stops the wrong unit (service-only, or a misspelled unit) leaves
    /// the armed-timer poison window open.
    #[test]
    fn restore_timer_disarm_argv_targets_the_refresh_timer() {
        assert_eq!(
            super::refresh_timer_disarm_argv(),
            ["systemctl", "stop", "rustynetd-assignment-refresh.timer"]
        );
    }

    /// Strict-vs-tolerant stop: only a timer that answered "active" as found
    /// makes a failed stop an error; every other as-found state tolerates a
    /// failed stop (there was no armed timer to begin with).
    #[test]
    fn timer_found_active_gate_is_exact() {
        assert!(snapshot("h", None, Some("active")).timer_found_active());
        assert!(snapshot("h", None, Some("active\n")).timer_found_active());
        assert!(!snapshot("h", None, Some("inactive")).timer_found_active());
        assert!(!snapshot("h", None, Some("unknown")).timer_found_active());
        assert!(!snapshot("h", None, Some("")).timer_found_active());
        assert!(!snapshot("h", None, None).timer_found_active());
    }

    /// Restore always covers BOTH halves — env action dispatch AND the timer
    /// disarm — in that order, on the one path shared by the strict
    /// success-path call and the Drop backstop. (Mutant: restore the env but
    /// skip the timer, or stop the timer without touching the env.)
    #[test]
    fn restore_covers_env_and_timer_in_order_on_one_shared_path() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        // Scan only the implementation region: this tests module quotes the
        // restore function's name and would otherwise match itself.
        let impl_end = source
            .find("\nmod tests {")
            .expect("tests module must follow the implementation");
        let impl_source = &source[..impl_end];
        let fn_start = impl_source
            .find("fn restore_participant_refresh_state(")
            .expect("restore function must exist");
        let fn_body = &impl_source[fn_start..];
        let env_action = fn_body
            .find("refresh_env_restore_action(snapshot)")
            .expect("restore must dispatch on the captured env");
        let disarm = fn_body
            .find("refresh_timer_disarm_argv()")
            .expect("restore must disarm the refresh timer");
        assert!(
            env_action < disarm,
            "the timer must be disarmed after the env action, never before: {fn_body}"
        );
        // One shared path: no second, divergent restore implementation.
        assert_eq!(
            impl_source
                .matches("fn restore_participant_refresh_state(")
                .count(),
            1,
            "restore must have exactly one implementation"
        );
    }

    /// The success path restores STRICTLY (a failed restore fails the stage)
    /// and only then clears the Drop backstop. (Mutant: drop the strict
    /// restore and rely on the best-effort Drop, which swallows failures and
    /// would let the stage pass with the poison still installed.)
    #[test]
    fn success_path_restores_pre_toggle_state_strictly_before_returning() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let release = run_body
            .find("bundle_swap_fence.release()")
            .expect("the success path must release the bundle-swap fence");
        let strict_restore = run_body[release..]
            .find("restore_participant_refresh_state(&ctx, snapshot)")
            .expect("the success path must strictly restore the pre-toggle state after the fence releases");
        let clear = run_body[release..]
            .find("cleanup.refresh_env_snapshots = Vec::new()")
            .expect("the success path must clear the Drop backstop after the strict restore");
        assert!(
            strict_restore < clear,
            "the backstop is cleared only after the strict restore succeeded"
        );
        assert!(
            run_body.contains(".map_err(|err| {\n            format!(\n                \"restore pre-toggle assignment-refresh state on {}"),
            "a failed restore must fail the stage, not warn"
        );
    }

    /// The pre-toggle capture happens BEFORE the toggle installs its own env
    /// on every participant, and the snapshots land on the cleanup guard.
    /// (Mutant: capture after the install — the snapshot then holds the
    /// TOGGLE's env and "restore" reinstalls the poison.)
    #[test]
    fn pre_toggle_env_capture_precedes_toggle_env_install() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let run_start = source.find("\nfn run(").expect("run() must exist");
        let run_end = source
            .find("struct LanToggleCleanup")
            .expect("LanToggleCleanup must follow run()");
        let run_body = &source[run_start..run_end];
        let capture = run_body
            .find("capture_refresh_env_snapshot(&ctx, host)")
            .expect("run() must capture the pre-toggle state");
        let install = run_body
            .find("install_assignment_refresh_env(&ctx, &exit_host, &exit_refresh_local)")
            .expect("run() must install the toggle env");
        assert!(
            capture < install,
            "the as-found snapshot must be taken before the first toggle env install ({capture} >= {install})"
        );
        assert!(
            run_body.contains("cleanup.refresh_env_snapshots = refresh_env_snapshots.clone()"),
            "the snapshots must arm the cleanup guard's Drop backstop"
        );
    }

    /// The Drop backstop restores every snapshot best-effort and is armed
    /// from the same snapshots the success path consumes — an error path
    /// between capture and success must hit the restore.
    #[test]
    fn cleanup_drop_backstop_restores_the_captured_snapshots() {
        let source = include_str!("live_linux_lan_toggle_test.rs");
        let drop_start = source
            .find("impl Drop for LanToggleCleanup")
            .expect("the cleanup Drop must exist");
        let drop_body = &source[drop_start..];
        let backstop = drop_body
            .find("restore_participant_refresh_state(&self.ctx, snapshot)")
            .expect("the Drop backstop must restore the pre-toggle state");
        let client_restore = drop_body
            .find("install_assignment_bundle_atomically(")
            .expect("the client's exit-signed restore must follow");
        assert!(
            backstop < client_restore,
            "the env restore runs before the assignment restore: the env poison outlives a wrong assignment"
        );
    }
}
