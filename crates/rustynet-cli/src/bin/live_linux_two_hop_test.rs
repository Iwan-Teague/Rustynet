#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]
// Track B Phase 28 transition: still calls the deprecated
// `capture_root` shim. Phase 29 rewrites on the new
// `RemoteShellHost` trait. Allow until then so `-D warnings` passes.
#![allow(deprecated)]

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, append_env_assignment, capture_root, create_workspace, enforce_host,
    ensure_pinned_known_hosts_file, ensure_safe_spec, ensure_safe_token, git_head_commit,
    issue_assignment_bundles_from_env, issue_traversal_bundles_from_env,
    load_home_known_hosts_path, no_plaintext_passphrase_check, remote_src_dir, require_command,
    resolved_target_address, retry_root, run_root, scp_to, seed_known_hosts, shell_quote,
    ssh_status, status, status_code, unix_now, wait_for_daemon_socket,
    write_assignment_refresh_env, write_file,
};

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

/// X6 taxonomy classifier shared in spirit with the other live-lab
/// test binaries. Kept local to each binary so they remain
/// independently buildable.
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
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;

    // Wave 2 (W2-B): `--platform macos|windows` now runs the REAL two-hop
    // data-plane proof instead of fail-closing at the gate. The per-OS
    // differences live in runtime `match config.platform` branches inside the
    // data-plane probe helpers (mesh-IP discovery, reachability/TTL ping, and
    // the default-route precondition), modeled on `live_linux_relay_test.rs`.
    // Linux behaviour is byte-identical to before.
    //
    // REVIEW (W2-B daemon-side gap, expected to surface on a live run): the
    // *control-plane orchestration* in this binary above the data-plane proof —
    // signed-bundle issuance/distribution, `enforce_host`, `route advertise`,
    // the `status` capture, and the `/run/rustynet/rustynetd.sock` socket path
    // wrapped in POSIX `sudo -n sh -lc` — is still Linux-shaped (it predates
    // this Wave and is out of scope for W2-B, whose owned surface is the
    // data-plane proof). On macOS the daemon socket is
    // `/private/var/run/rustynet/rustynetd.sock` and on Windows there is no
    // `sudo`; those steps will fail-closed honestly on a live mac/win guest
    // until a follow-up Wave ports the control plane. Additionally, macOS/
    // Windows acting as the INTERMEDIATE forwarding hop (the entry node that
    // terminates the client tunnel and re-exits onward) is NOT confirmed to be
    // daemon-supported — if it is unsupported the live run fails-closed (no
    // TTL-2 delta, no end-to-end reply), which is the honest, intended outcome.
    // This is a test port, not a claim that the role works on that OS.

    let root_dir = live_lab_support::repo_root()?;

    for command in [
        "cargo",
        "git",
        "ssh",
        "scp",
        "ssh-keygen",
        "awk",
        "sed",
        "openssl",
        "xxd",
        "mktemp",
        "chmod",
        "tr",
    ] {
        require_command(command)?;
    }

    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match &config.pinned_known_hosts_file {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("two-hop-live")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;
    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[two-hop] starting live two-hop validation")?;

    for host in [
        &config.final_exit_host,
        &config.client_host,
        &config.entry_host,
        &config.second_client_host,
    ] {
        verify_sudo(&config.ssh_identity_file, &work_known_hosts, host)?;
    }

    logger.line("[two-hop] collecting wireguard public keys")?;
    let final_exit_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
    )?;
    let client_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    let entry_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
    )?;
    let second_client_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
    )?;

    let final_exit_addr = resolved_target_address(&config.final_exit_host)?;
    let client_addr = resolved_target_address(&config.client_host)?;
    let entry_addr = resolved_target_address(&config.entry_host)?;
    let second_client_addr = resolved_target_address(&config.second_client_host)?;

    // Node entry layout is node_id|endpoint|public_key|owner|hostname|os|
    // tags_csv|capabilities_csv. The assignment issuer reads capabilities from
    // field 7 (parse_assignment_nodes), while the traversal/DNS issuer reads
    // them from field 3 (parse_generic_traversal_node_specs). To satisfy both
    // parsers the canonical lab form repeats the capability CSV in field 3 and
    // field 7 with the intervening owner/hostname/os/tags fields left empty
    // (mirrors build_onehop_specs in live_linux_lab_orchestrator.sh). Using a
    // bare node_id|endpoint|key|caps form puts the caps in the owner slot and
    // leaves field 7 empty, so the assignment bundle defaults every peer to
    // client and the daemon rejects it ("route peer <id> lacks signed
    // relay_host or exit_server capability").
    //
    // The two-hop chain is client -> entry -> final_exit, where the entry node
    // is the intermediate exit: it terminates the client's tunnel and re-exits
    // toward the final exit (ASSIGNMENTS_SPEC below sets client|entry and
    // entry|final_exit). The entry node is enforced as the admin role (it
    // advertises an exit route), so its assignment intent must include the
    // anchor capability (NodeRole::Admin requires Anchor); it also needs
    // exit_server to serve client traffic as an exit and client to consume the
    // final exit. The final exit is likewise admin (anchor) + exit_server.
    let nodes_spec = format!(
        "{}|{}:51820|{}|anchor,exit_server||||anchor,exit_server;{}|{}:51820|{}|client,relay_host||||client,relay_host;{}|{}:51820|{}|anchor,client,relay_host,exit_server||||anchor,client,relay_host,exit_server;{}|{}:51820|{}|client,relay_host||||client,relay_host",
        config.final_exit_node_id,
        final_exit_addr,
        final_exit_pub_hex,
        config.client_node_id,
        client_addr,
        client_pub_hex,
        config.entry_node_id,
        entry_addr,
        entry_pub_hex,
        config.second_client_node_id,
        second_client_addr,
        second_client_pub_hex,
    );
    // The client deliberately does NOT peer directly with the final exit.
    //
    // Rationale is DETERMINISM, not unsatisfiability. While `client|final_exit` was in
    // this spec the client had TWO available paths to the final exit's mesh IP — its own
    // direct tunnel and the entry's `0.0.0.0/0` — and the measured per-hop delta was not
    // stable across runs: 1 at `c66887a8c` (baseline 64 / two-hop 63), 0 at `050743825`
    // (64 / 64), and -1 at `f9388393` (baseline unreachable). An exact oracle cannot rest
    // on an input that depends on which of two paths the traffic happens to take.
    // Removing the pair leaves exactly one path.
    //
    // NOTE, corrected 2026-07-26: an earlier version of this comment claimed the pair
    // meant the probe "could never observe forwarding" (always TTL 64, zero decrement).
    // That is FALSE — `c66887a8c` measured 63 *with* the pair present, i.e. forwarding
    // was observed. The old topology produced both 63 and 64 on different runs, which is
    // exactly the non-determinism this strip removes.
    //
    // With the pair removed the client has exactly one peer (the entry), so the
    // final exit's mesh IP matches the client's `0.0.0.0/0` and the probe
    // traverses the real two-hop chain. The reply still comes back because the
    // entry masquerades the hairpin (`phase10.rs:2285-2299`) — that SNAT is
    // what gives the final exit a route to the requester, since after this
    // strip its peers carry only `entry/32` and `second_client/32`. See
    // `NodeEngineFlipDispositions_2026-07-24.md` D1 for the TTL derivation.
    let allow_spec = format!(
        "{}|{};{}|{};{}|{};{}|{};{}|{};{}|{}",
        config.client_node_id,
        config.entry_node_id,
        config.entry_node_id,
        config.client_node_id,
        config.entry_node_id,
        config.final_exit_node_id,
        config.final_exit_node_id,
        config.entry_node_id,
        config.second_client_node_id,
        config.final_exit_node_id,
        config.final_exit_node_id,
        config.second_client_node_id,
    );
    let assignments_spec = format!(
        "{}|-;{}|{};{}|{};{}|{}",
        config.final_exit_node_id,
        config.client_node_id,
        config.entry_node_id,
        config.entry_node_id,
        config.final_exit_node_id,
        config.second_client_node_id,
        config.final_exit_node_id,
    );
    ensure_safe_spec("NODES_SPEC", &nodes_spec)?;
    ensure_safe_spec("ALLOW_SPEC", &allow_spec)?;
    ensure_safe_spec("ASSIGNMENTS_SPEC", &assignments_spec)?;

    let issue_env = workspace.path().join("rn_issue_twohop.env");
    write_file(&issue_env, "")?;
    append_env_assignment(&issue_env, "FINAL_EXIT_NODE_ID", &config.final_exit_node_id)?;
    append_env_assignment(&issue_env, "CLIENT_NODE_ID", &config.client_node_id)?;
    append_env_assignment(&issue_env, "ENTRY_NODE_ID", &config.entry_node_id)?;
    append_env_assignment(
        &issue_env,
        "SECOND_CLIENT_NODE_ID",
        &config.second_client_node_id,
    )?;
    append_env_assignment(&issue_env, "NODES_SPEC", &nodes_spec)?;
    append_env_assignment(&issue_env, "ALLOW_SPEC", &allow_spec)?;
    append_env_assignment(&issue_env, "ASSIGNMENTS_SPEC", &assignments_spec)?;

    logger.line(
        format!(
            "[two-hop] issuing signed two-hop assignments on {}",
            config.final_exit_host
        )
        .as_str(),
    )?;
    issue_assignment_bundles_from_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &issue_env,
        "/tmp/rn_issue_twohop.env",
    )?;

    let assign_pub_local = workspace.path().join("assignment.pub");
    let final_exit_assignment_local = workspace.path().join("assignment-final-exit");
    let client_assignment_local = workspace.path().join("assignment-client");
    let entry_assignment_local = workspace.path().join("assignment-entry");
    let second_client_assignment_local = workspace.path().join("assignment-second-client");

    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        &assign_pub_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.final_exit_node_id
        ),
        &final_exit_assignment_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.client_node_id
        ),
        &client_assignment_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.entry_node_id
        ),
        &entry_assignment_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.second_client_node_id
        ),
        &second_client_assignment_local,
    )?;

    // ATOMICITY FENCE — see `NodeEngineFlipDispositions_2026-07-24.md` D1.
    //
    // The daemon fail-closes on ANY set inequality between the assignment
    // bundle's peer set (`envelope.bundle.peers`, `daemon.rs:8919`) and the
    // traversal bundle's target index, in BOTH directions
    // (`apply_traversal_authority_to_peers`, `daemon.rs:6693-6755`), and
    // escalates to `restriction_mode=Permanent` after
    // `DEFAULT_MAX_RECONCILE_FAILURES` = 5 rejections (`daemon.rs:338`,
    // `:9250-9257`) — which tears the tunnel down.
    //
    // Those two artifacts are ONE atomic pair. In production a single
    // `/etc/rustynet/assignment-refresh.env` mints BOTH of them
    // (`ops refresh-assignment` -> `refresh_local_traversal_bundle_from_specs`,
    // `main.rs:14345`, called before the assignment-TTL short-circuit), so
    // equality holds structurally: either both halves refresh together or
    // neither does. This test narrows the inherited mesh and so must rewrite
    // both halves — and installing them one at a time violates that invariant,
    // leaving a window in which the narrowed assignment is paired with the
    // setup's full-mesh traversal index. That window is what produced
    // `snapshot contains unmanaged peers: <aux>,<extra>` on the entry and tore
    // down `rustynet0` before the data-plane probes ran.
    //
    // So quiesce every chain node across the whole swap: stop the 60s
    // assignment-refresh timer (it would otherwise re-mint and poke
    // `state refresh` mid-swap) and stop the daemon, so no reconcile observes a
    // half-swapped pair at all — regardless of which artifact is re-read on
    // which code path. `enforce_host` below brings each daemon back up COLD onto
    // the completed, consistent pair, and the timer is resumed immediately
    // after.
    //
    // This changes NO daemon behaviour. Set equality, the failure threshold, the
    // managed-peer definition, and signature/freshness/anti-replay validation
    // are all untouched: the invalid intermediate state is removed, not
    // tolerated (CLAUDE.md 13.2).
    logger.line(
        "[two-hop] quiescing daemons + assignment-refresh timers for the atomic bundle swap",
    )?;
    let swap_fence = BundleSwapFence::quiesce(
        &config.ssh_identity_file,
        &work_known_hosts,
        &[
            config.final_exit_host.as_str(),
            config.client_host.as_str(),
            config.entry_host.as_str(),
            config.second_client_host.as_str(),
        ],
    )?;

    logger.line("[two-hop] distributing signed assignments")?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &assign_pub_local,
        &final_exit_assignment_local,
    )?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &assign_pub_local,
        &client_assignment_local,
    )?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &assign_pub_local,
        &entry_assignment_local,
    )?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        &assign_pub_local,
        &second_client_assignment_local,
    )?;

    let final_exit_refresh_local = workspace.path().join("assignment-refresh-final-exit.env");
    let client_refresh_local = workspace.path().join("assignment-refresh-client.env");
    let entry_refresh_local = workspace.path().join("assignment-refresh-entry.env");
    let second_client_refresh_local = workspace
        .path()
        .join("assignment-refresh-second-client.env");
    write_assignment_refresh_env(
        &final_exit_refresh_local,
        &config.final_exit_node_id,
        &nodes_spec,
        &allow_spec,
        None,
    )?;
    write_assignment_refresh_env(
        &client_refresh_local,
        &config.client_node_id,
        &nodes_spec,
        &allow_spec,
        Some(&config.entry_node_id),
    )?;
    write_assignment_refresh_env(
        &entry_refresh_local,
        &config.entry_node_id,
        &nodes_spec,
        &allow_spec,
        Some(&config.final_exit_node_id),
    )?;
    write_assignment_refresh_env(
        &second_client_refresh_local,
        &config.second_client_node_id,
        &nodes_spec,
        &allow_spec,
        Some(&config.final_exit_node_id),
    )?;

    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &final_exit_refresh_local,
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &client_refresh_local,
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &entry_refresh_local,
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        &second_client_refresh_local,
    )?;

    let traversal_env = workspace.path().join("rn_issue_twohop_traversal.env");
    write_file(&traversal_env, "")?;
    append_env_assignment(&traversal_env, "NODES_SPEC", &nodes_spec)?;
    append_env_assignment(&traversal_env, "ALLOW_SPEC", &allow_spec)?;

    logger.line("[two-hop] issuing signed traversal bundles for two-hop topology")?;
    issue_traversal_bundles_from_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &traversal_env,
        "/tmp/rn_issue_twohop_traversal.env",
    )?;

    let traversal_pub_local = workspace.path().join("traversal.pub");
    let final_exit_traversal_local = workspace.path().join("traversal-final-exit");
    let client_traversal_local = workspace.path().join("traversal-client");
    let entry_traversal_local = workspace.path().join("traversal-entry");
    let second_client_traversal_local = workspace.path().join("traversal-second-client");
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "/run/rustynet/traversal-issue/rn-traversal.pub",
        &traversal_pub_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.final_exit_node_id
        ),
        &final_exit_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.client_node_id
        ),
        &client_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.entry_node_id
        ),
        &entry_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.second_client_node_id
        ),
        &second_client_traversal_local,
    )?;

    logger.line("[two-hop] distributing signed traversal bundles")?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &traversal_pub_local,
        &final_exit_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &traversal_pub_local,
        &client_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &traversal_pub_local,
        &entry_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        &traversal_pub_local,
        &second_client_traversal_local,
    )?;

    let dns_zone_name =
        env::var("RUSTYNET_DNS_ZONE_NAME").unwrap_or_else(|_| "rustynet".to_owned());
    ensure_safe_token("dns-zone-name", dns_zone_name.as_str())?;
    let dns_zone_env = workspace.path().join("rn_issue_twohop_dns_zone.env");
    write_file(&dns_zone_env, "")?;
    append_env_assignment(&dns_zone_env, "NODES_SPEC", &nodes_spec)?;
    append_env_assignment(&dns_zone_env, "ALLOW_SPEC", &allow_spec)?;
    append_env_assignment(&dns_zone_env, "DNS_ZONE_NAME", &dns_zone_name)?;

    logger.line("[two-hop] issuing signed DNS zone bundles for two-hop topology")?;
    issue_dns_zone_bundles_from_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &dns_zone_env,
        "/tmp/rn_issue_twohop_dns_zone.env",
    )?;

    let dns_zone_pub_local = workspace.path().join("dns-zone.pub");
    let final_exit_dns_zone_local = workspace.path().join("dns-zone-final-exit");
    let client_dns_zone_local = workspace.path().join("dns-zone-client");
    let entry_dns_zone_local = workspace.path().join("dns-zone-entry");
    let second_client_dns_zone_local = workspace.path().join("dns-zone-second-client");
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "/run/rustynet/dns-zone-issue/rn-dns-zone.pub",
        &dns_zone_pub_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/dns-zone-issue/rn-dns-zone-{}.dns-zone",
            config.final_exit_node_id
        ),
        &final_exit_dns_zone_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/dns-zone-issue/rn-dns-zone-{}.dns-zone",
            config.client_node_id
        ),
        &client_dns_zone_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/dns-zone-issue/rn-dns-zone-{}.dns-zone",
            config.entry_node_id
        ),
        &entry_dns_zone_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/dns-zone-issue/rn-dns-zone-{}.dns-zone",
            config.second_client_node_id
        ),
        &second_client_dns_zone_local,
    )?;

    logger.line("[two-hop] distributing signed DNS zone bundles")?;
    install_dns_zone_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &dns_zone_pub_local,
        &final_exit_dns_zone_local,
    )?;
    install_dns_zone_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &dns_zone_pub_local,
        &client_dns_zone_local,
    )?;
    install_dns_zone_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &dns_zone_pub_local,
        &entry_dns_zone_local,
    )?;
    install_dns_zone_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        &dns_zone_pub_local,
        &second_client_dns_zone_local,
    )?;

    logger.line("[two-hop] enforcing runtime roles")?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "admin",
        &config.final_exit_node_id,
        &remote_src_dir(&config.final_exit_host),
        &config.ssh_allow_cidrs,
    )?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "client",
        &config.client_node_id,
        &remote_src_dir(&config.client_host),
        &config.ssh_allow_cidrs,
    )?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        "admin",
        &config.entry_node_id,
        &remote_src_dir(&config.entry_host),
        &config.ssh_allow_cidrs,
    )?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        "client",
        &config.second_client_node_id,
        &remote_src_dir(&config.second_client_host),
        &config.ssh_allow_cidrs,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;

    // Release the atomicity fence: both halves of the signed pair are installed and
    // every daemon has come up cold onto them, so the periodic refresh may resume.
    //
    // Belt-and-braces rather than strictly required. `enforce_host` runs
    // `install-systemd`, which already restarts the refresh timer where
    // auto-refresh is enabled — and this test enables it on all four chain nodes.
    // Restarting explicitly keeps the quiesce/resume pair symmetric (so the Drop
    // guard has a matching success path) and means the stage does not depend on
    // that side effect of another command.
    //
    // Note the freshness pressure is much lower here than in production: the lab
    // bakes `RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400`
    // (`vm_lab/orchestrator/adapter/linux_install.rs:205-206`), a 24h window,
    // whereas 120s is the *production* default (`ops_install_systemd.rs:300`). So
    // the resume is not what keeps the in-stage traversal state fresh; do not
    // justify it that way.
    logger.line("[two-hop] resuming assignment-refresh timers")?;
    swap_fence.release()?;

    // After enforce_host the daemon comes up cold and stays in
    // restricted-safe mode until it ingests fresh signed trust evidence.
    // The route advertise call below is a mutating IPC command and is
    // refused while restricted-safe is set, so refresh trust on every
    // node first. Mirrors the exit_handoff test's pre-route-advertise
    // refresh; without it `route advertise 0.0.0.0/0` fails with
    // "daemon is in restricted-safe mode" on the final exit.
    logger.line("[two-hop] refreshing signed trust evidence on all nodes")?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
    )?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
    )?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
    )?;

    // The traversal coordination records inside each signed bundle have a
    // hard-capped 30-second TTL (MAX_COORDINATION_TTL_SECS in
    // crates/rustynetd/src/traversal.rs). Between the initial issuance
    // above and now (post enforce_host x4 + wait_for_socket x4 +
    // refresh_trust_evidence x4) significantly more than 30s have
    // elapsed, so each daemon's reconcile loop sees the stored
    // coordination as expired, fails 5+ times, and escalates to
    // restriction_mode=Permanent. Once Permanent, the next mutating
    // IPC (route advertise below) is refused with "daemon is in
    // restricted-safe mode" — the failure mode that broke this stage
    // in livelab4 even with the trust refresh in place.
    //
    // Re-issue + re-distribute traversal bundles so each peer has a
    // freshly-signed coordination record (new 30s TTL window starting
    // now), then run `state refresh` IPC on every node. State refresh
    // is non-mutating (exempt from the restricted-safe gate) and on
    // success explicitly resets restriction_mode to None and clears
    // reconcile_failures (daemon.rs:3506-3508). The route advertise
    // that follows then sees a daemon out of restricted-safe.
    logger.line("[two-hop] re-issuing signed traversal bundles before route advertise")?;
    issue_traversal_bundles_from_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &traversal_env,
        "/tmp/rn_issue_twohop_traversal.env",
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.final_exit_node_id
        ),
        &final_exit_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.client_node_id
        ),
        &client_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.entry_node_id
        ),
        &entry_traversal_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
            config.second_client_node_id
        ),
        &second_client_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &traversal_pub_local,
        &final_exit_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &traversal_pub_local,
        &client_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &traversal_pub_local,
        &entry_traversal_local,
    )?;
    install_traversal_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
        &traversal_pub_local,
        &second_client_traversal_local,
    )?;

    logger.line("[two-hop] forcing signed-state refresh to clear restricted-safe")?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
    )?;

    logger.line("[two-hop] advertising default route on final exit and entry relay")?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {} route advertise 0.0.0.0/0",
            live_lab_support::REMOTE_RUSTYNET_BIN
        ),
    )?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {} route advertise 0.0.0.0/0",
            live_lab_support::REMOTE_RUSTYNET_BIN
        ),
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
    )?;
    refresh_signed_state(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.second_client_host,
    )?;

    let mut client_status = String::new();
    let mut entry_status = String::new();
    let mut final_exit_status = String::new();
    let mut second_client_status = String::new();
    let mut client_route = String::new();
    let mut second_client_route = String::new();
    for attempt in 0..=20 {
        client_status = status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
        )?;
        entry_status = status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.entry_host,
        )?;
        final_exit_status = status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.final_exit_host,
        )?;
        second_client_status = status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.second_client_host,
        )?;
        client_route = capture_root(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            default_route_probe_command(config.platform, TWO_HOP_PUBLIC_PROBE_TARGET).as_str(),
        )?;
        second_client_route = capture_root(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.second_client_host,
            default_route_probe_command(config.platform, TWO_HOP_PUBLIC_PROBE_TARGET).as_str(),
        )?;
        if two_hop_runtime_ready(
            &config,
            &client_status,
            &entry_status,
            &final_exit_status,
            &second_client_status,
            &client_route,
            &second_client_route,
        ) {
            break;
        }
        if attempt < 20 {
            if attempt % 5 == 4 {
                refresh_signed_state(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    &config.final_exit_host,
                )?;
                refresh_signed_state(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    &config.client_host,
                )?;
                refresh_signed_state(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    &config.entry_host,
                )?;
                refresh_signed_state(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    &config.second_client_host,
                )?;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    let entry_wg_endpoints = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        "wg show rustynet0 endpoints || true",
    )?;
    let entry_managed_peer_endpoints =
        status_field(&entry_status, "managed_peer_endpoints").unwrap_or_else(|| "none".to_owned());
    let entry_managed_peer_endpoints_error =
        status_field(&entry_status, "managed_peer_endpoints_error")
            .unwrap_or_else(|| "none".to_owned());
    let client_plaintext_check = no_plaintext_passphrase_check(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    let entry_plaintext_check = no_plaintext_passphrase_check(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
    )?;
    let final_exit_plaintext_check = no_plaintext_passphrase_check(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
    )?;

    // ─── F0.8: real two-hop data-plane + per-hop proof ────────────────────
    //
    // The status-string checks above (exit_node=…, serving_exit_node=true,
    // state=ExitActive) and the `dev rustynet0` route only prove the control
    // plane *intends* to two-hop; they never move a packet. Below we move
    // real packets and assert two independent, behavioural facts:
    //
    //   1. END-TO-END REACHABILITY (the actual proof): from the client, ping
    //      a PUBLIC target whose only route is `0.0.0.0/0 dev rustynet0`
    //      (asserted as a precondition above). A returning echo reply proves
    //      the datagram traversed client → entry(intermediate exit) →
    //      final_exit → internet and came back — i.e. the full two-hop chain
    //      actually forwarded traffic, not just advertised that it would.
    //
    //   2. PER-HOP EVIDENCE (TTL−2): the reply TTL observed at the client for
    //      a ping to the FINAL-EXIT mesh IP is exactly 2 lower than for a ping
    //      to the ENTRY mesh IP. Both reply originators are Linux (initial TTL
    //      64), so the only thing that can move the delta is IP forwarding:
    //      the entry-mesh reply is a direct tunnel peer (baseline), while the
    //      final-exit-mesh reply crosses the entry's forwarding stack one extra
    //      time in EACH direction (request out, reply back) — a clean −2. This
    //      directly evidences that the entry node is *relaying onward*, which
    //      no status string can fake.
    //
    // Design note (TTL−2 vs forwarded-counter): the spec offered either a TTL
    // decrement of exactly 2 OR an entry forwarded-packet counter delta. We
    // pick TTL−2 because the existing argv-only `capture_root`/`ssh_status`
    // ping primitives expose the reply TTL directly and require no privileged
    // /proc/net/snmp scraping, extra synchronisation, or assumptions about
    // background traffic polluting a global forwarding counter. TTL−2 is a
    // per-packet, self-contained, deterministic per-hop signal observable
    // entirely through primitives already used by this binary.
    //
    // Fail-closed discipline (mirrors `probe_attempted` in the ipv6_leak
    // tests): every probe records whether it actually executed. A probe that
    // could not run (mesh-IP discovery failed, ping never produced parseable
    // output) leaves `attempted=false`, and the evaluator treats a never-run
    // probe as a FAIL — never a silent pass.
    logger.line("[two-hop] discovering mesh tunnel addresses for data-plane probe")?;
    let entry_mesh_ipv4 = discover_mesh_ipv4(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        config.platform,
    )?;
    let final_exit_mesh_ipv4 = discover_mesh_ipv4(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        config.platform,
    )?;
    logger.line(
        format!(
            "[two-hop] entry mesh ipv4={} final-exit mesh ipv4={}",
            entry_mesh_ipv4.as_deref().unwrap_or("<undiscovered>"),
            final_exit_mesh_ipv4.as_deref().unwrap_or("<undiscovered>")
        )
        .as_str(),
    )?;

    // Wait (bounded, fail-closed) for the cold-restarted chain to actually carry
    // traffic before measuring it. See `await_two_hop_path_ready`.
    let readiness = match final_exit_mesh_ipv4.as_deref() {
        Some(ip) => await_two_hop_path_ready(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            ip,
            config.platform,
            &mut logger,
        )?,
        None => TwoHopReadiness::not_attempted(),
    };
    logger.line(
        format!(
            "[two-hop] path readiness attempted={} became_reachable={} attempts={} waited_secs={}",
            readiness.attempted,
            readiness.became_reachable,
            readiness.attempts,
            readiness.waited_secs
        )
        .as_str(),
    )?;

    logger.line("[two-hop] running end-to-end data-plane reachability probe through chain")?;
    let end_to_end = probe_end_to_end_reachability(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        TWO_HOP_PUBLIC_PROBE_TARGET,
        config.platform,
    );
    logger.line(
        format!(
            "[two-hop] end-to-end probe attempted={} reachable={}",
            end_to_end.attempted, end_to_end.reachable
        )
        .as_str(),
    )?;

    logger
        .line("[two-hop] measuring per-hop TTL baseline (entry mesh) and two-hop (final exit)")?;
    let baseline_ttl = match entry_mesh_ipv4.as_deref() {
        Some(ip) => probe_reply_ttl(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            ip,
            config.platform,
        ),
        None => TtlProbe::not_attempted(),
    };
    let two_hop_ttl = match final_exit_mesh_ipv4.as_deref() {
        Some(ip) => probe_reply_ttl(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            ip,
            config.platform,
        ),
        None => TtlProbe::not_attempted(),
    };
    logger.line(
        format!(
            "[two-hop] baseline(entry) ttl attempted={} ttl={:?}; two-hop(final-exit) ttl attempted={} ttl={:?}",
            baseline_ttl.attempted, baseline_ttl.ttl, two_hop_ttl.attempted, two_hop_ttl.ttl
        )
        .as_str(),
    )?;

    let dataplane_proof =
        evaluate_two_hop_dataplane_proof(&end_to_end, &baseline_ttl, &two_hop_ttl);

    logger.line("[two-hop] final client status")?;
    logger.block(&(client_status.clone() + "\n"))?;
    logger.line("[two-hop] final entry status")?;
    logger.block(&(entry_status.clone() + "\n"))?;
    logger.line("[two-hop] final exit status")?;
    logger.block(&(final_exit_status.clone() + "\n"))?;
    logger.line("[two-hop] final second client status")?;
    logger.block(&(second_client_status.clone() + "\n"))?;
    logger.line("[two-hop] client route")?;
    logger.block(&(client_route.clone() + "\n"))?;
    logger.line("[two-hop] second client route")?;
    logger.block(&(second_client_route.clone() + "\n"))?;
    logger.line("[two-hop] entry managed peer endpoints (backend-authoritative)")?;
    logger.block(&(entry_managed_peer_endpoints.clone() + "\n"))?;
    logger.line("[two-hop] entry wg endpoints (debug only)")?;
    logger.block(&(entry_wg_endpoints.clone() + "\n"))?;
    logger.line("[two-hop] data-plane proof summary")?;
    logger.block(&(dataplane_proof.summary_line() + "\n"))?;

    let check_client_exit_is_entry = if client_status
        .contains(&format!("exit_node={}", config.entry_node_id))
        && client_status.contains("state=ExitActive")
    {
        "pass"
    } else {
        "fail"
    };
    let check_entry_exit_is_final =
        if entry_status.contains(&format!("exit_node={}", config.final_exit_node_id)) {
            "pass"
        } else {
            "fail"
        };
    let check_entry_serves_exit = if entry_status.contains("serving_exit_node=true") {
        "pass"
    } else {
        "fail"
    };
    let check_final_exit_serves = if final_exit_status.contains("serving_exit_node=true") {
        "pass"
    } else {
        "fail"
    };
    let check_client_route_rustynet = if route_uses_tunnel(config.platform, &client_route) {
        "pass"
    } else {
        "fail"
    };
    let check_second_client_route_rustynet =
        if route_uses_tunnel(config.platform, &second_client_route) {
            "pass"
        } else {
            "fail"
        };
    let check_managed_dns_fresh_all_nodes = if managed_dns_state_is_valid(&client_status)
        && managed_dns_state_is_valid(&entry_status)
        && managed_dns_state_is_valid(&final_exit_status)
        && managed_dns_state_is_valid(&second_client_status)
    {
        "pass"
    } else {
        "fail"
    };
    let check_entry_managed_peer_endpoints_visible = if managed_peer_endpoints_include(
        &entry_managed_peer_endpoints,
        &entry_managed_peer_endpoints_error,
        &[
            (&config.client_node_id, client_addr.as_str(), 51820),
            (&config.final_exit_node_id, final_exit_addr.as_str(), 51820),
        ],
    ) {
        "pass"
    } else {
        "fail"
    };
    let check_no_plaintext_passphrases = if client_plaintext_check.trim()
        == "no-plaintext-passphrase-files"
        && entry_plaintext_check.trim() == "no-plaintext-passphrase-files"
        && final_exit_plaintext_check.trim() == "no-plaintext-passphrase-files"
    {
        "pass"
    } else {
        "fail"
    };
    // F0.8 behavioural proofs. These are the load-bearing data-plane
    // assertions; the status-string checks above are now preconditions only.
    let check_two_hop_end_to_end_reachable = if dataplane_proof.end_to_end_reachable {
        "pass"
    } else {
        "fail"
    };
    let check_two_hop_per_hop_ttl_decrement = if dataplane_proof.per_hop_ttl_decrement_ok {
        "pass"
    } else {
        "fail"
    };

    let overall = [
        check_client_exit_is_entry,
        check_entry_exit_is_final,
        check_entry_serves_exit,
        check_final_exit_serves,
        check_client_route_rustynet,
        check_second_client_route_rustynet,
        check_managed_dns_fresh_all_nodes,
        check_entry_managed_peer_endpoints_visible,
        check_no_plaintext_passphrases,
        check_two_hop_end_to_end_reachable,
        check_two_hop_per_hop_ttl_decrement,
    ]
    .into_iter()
    .all(|value| value == "pass");

    let captured_at_utc = utc_now_string();
    let captured_at_unix = unix_now();
    let git_commit = config.git_commit.unwrap_or_else(|| {
        git_head_commit(&root_dir).unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        })
    });

    let report = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"mode\": \"live_linux_two_hop\",\n  \"evidence_mode\": \"measured\",\n  \"captured_at\": \"{}\",\n  \"captured_at_unix\": {},\n  \"git_commit\": \"{}\",\n  \"status\": \"{}\",\n  \"final_exit_host\": \"{}\",\n  \"client_host\": \"{}\",\n  \"entry_host\": \"{}\",\n  \"second_client_host\": \"{}\",\n  \"proof_sources\": {{\n    \"entry_peer_visibility\": \"managed_peer_endpoints\",\n    \"entry_peer_visibility_error_field\": \"managed_peer_endpoints_error\",\n    \"entry_peer_visibility_debug_only\": \"wg_show_endpoints\",\n    \"two_hop_end_to_end\": \"icmp_reachability_via_default_route_rustynet0\",\n    \"two_hop_per_hop\": \"reply_ttl_delta_entry_mesh_vs_final_exit_mesh\"\n  }},\n  \"dataplane\": {{\n    \"end_to_end_probe_target\": \"{}\",\n    \"end_to_end_probe_attempted\": {},\n    \"end_to_end_reachable\": {},\n    \"baseline_entry_mesh_ipv4\": \"{}\",\n    \"baseline_ttl_probe_attempted\": {},\n    \"baseline_reply_ttl\": {},\n    \"two_hop_final_exit_mesh_ipv4\": \"{}\",\n    \"two_hop_ttl_probe_attempted\": {},\n    \"two_hop_reply_ttl\": {},\n    \"per_hop_ttl_decrement\": {},\n    \"per_hop_ttl_decrement_ok\": {},\n    \"path_readiness_probe_attempted\": {},\n    \"path_readiness_became_reachable\": {},\n    \"path_readiness_attempts\": {},\n    \"path_readiness_waited_secs\": {}\n  }},\n  \"checks\": {{\n    \"client_exit_is_entry\": \"{}\",\n    \"entry_exit_is_final\": \"{}\",\n    \"entry_serves_exit\": \"{}\",\n    \"final_exit_serves\": \"{}\",\n    \"client_route_via_rustynet0\": \"{}\",\n    \"second_client_route_via_rustynet0\": \"{}\",\n    \"managed_dns_fresh_all_nodes\": \"{}\",\n    \"entry_peer_visibility\": \"{}\",\n    \"entry_managed_peer_endpoints_visible\": \"{}\",\n    \"no_plaintext_passphrase_files\": \"{}\",\n    \"two_hop_end_to_end_reachable\": \"{}\",\n    \"two_hop_per_hop_ttl_decrement\": \"{}\"\n  }},\n  \"source_artifacts\": [\n    \"{}\"\n  ]\n}}\n",
        captured_at_utc,
        captured_at_unix,
        git_commit,
        if overall { "pass" } else { "fail" },
        config.final_exit_host,
        config.client_host,
        config.entry_host,
        config.second_client_host,
        TWO_HOP_PUBLIC_PROBE_TARGET,
        end_to_end.attempted,
        end_to_end.reachable,
        entry_mesh_ipv4.as_deref().unwrap_or(""),
        baseline_ttl.attempted,
        baseline_ttl.ttl.map_or(-1_i64, i64::from),
        final_exit_mesh_ipv4.as_deref().unwrap_or(""),
        two_hop_ttl.attempted,
        two_hop_ttl.ttl.map_or(-1_i64, i64::from),
        dataplane_proof
            .per_hop_ttl_decrement
            .map_or(-1_i64, i64::from),
        dataplane_proof.per_hop_ttl_decrement_ok,
        readiness.attempted,
        readiness.became_reachable,
        readiness.attempts,
        readiness.waited_secs,
        check_client_exit_is_entry,
        check_entry_exit_is_final,
        check_entry_serves_exit,
        check_final_exit_serves,
        check_client_route_rustynet,
        check_second_client_route_rustynet,
        check_managed_dns_fresh_all_nodes,
        check_entry_managed_peer_endpoints_visible,
        check_entry_managed_peer_endpoints_visible,
        check_no_plaintext_passphrases,
        check_two_hop_end_to_end_reachable,
        check_two_hop_per_hop_ttl_decrement,
        config.log_path.display(),
    );
    write_file(&config.report_path, &report)?;
    logger.line(format!("[two-hop] report written: {}", config.report_path.display()).as_str())?;
    if !overall {
        return Err("two-hop validation failed".to_owned());
    }

    Ok(())
}

#[derive(Debug)]
struct Config {
    platform: live_lab_support::LiveLabPlatform,
    ssh_identity_file: PathBuf,
    final_exit_host: String,
    client_host: String,
    entry_host: String,
    second_client_host: String,
    final_exit_node_id: String,
    client_node_id: String,
    entry_node_id: String,
    second_client_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    log_path: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
    git_commit: Option<String>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: live_lab_support::LiveLabPlatform::Linux,
            ssh_identity_file: PathBuf::new(),
            final_exit_host: "debian@192.168.18.49".to_owned(),
            client_host: "debian@192.168.18.65".to_owned(),
            entry_host: "ubuntu@192.168.18.52".to_owned(),
            second_client_host: "fedora@192.168.18.51".to_owned(),
            final_exit_node_id: "exit-49".to_owned(),
            client_node_id: "client-65".to_owned(),
            entry_node_id: "client-52".to_owned(),
            second_client_node_id: "client-51".to_owned(),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            report_path: PathBuf::from("artifacts/phase10/live_linux_two_hop_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_two_hop.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform = live_lab_support::LiveLabPlatform::parse(
                        next_value(&mut iter, &arg)?.as_str(),
                    )?;
                }
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--final-exit-host" => config.final_exit_host = next_value(&mut iter, &arg)?,
                "--client-host" => config.client_host = next_value(&mut iter, &arg)?,
                "--entry-host" => config.entry_host = next_value(&mut iter, &arg)?,
                "--second-client-host" => config.second_client_host = next_value(&mut iter, &arg)?,
                "--final-exit-node-id" => config.final_exit_node_id = next_value(&mut iter, &arg)?,
                "--client-node-id" => config.client_node_id = next_value(&mut iter, &arg)?,
                "--entry-node-id" => config.entry_node_id = next_value(&mut iter, &arg)?,
                "--second-client-node-id" => {
                    config.second_client_node_id = next_value(&mut iter, &arg)?;
                }
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?));
                }
                "--git-commit" => config.git_commit = Some(next_value(&mut iter, &arg)?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_two_hop_test --ssh-identity-file <path> [options]".to_owned(),
            );
        }
        for (label, value) in [
            ("final-exit-host", config.final_exit_host.as_str()),
            ("client-host", config.client_host.as_str()),
            ("entry-host", config.entry_host.as_str()),
            ("second-client-host", config.second_client_host.as_str()),
            ("final-exit-node-id", config.final_exit_node_id.as_str()),
            ("client-node-id", config.client_node_id.as_str()),
            ("entry-node-id", config.entry_node_id.as_str()),
            (
                "second-client-node-id",
                config.second_client_node_id.as_str(),
            ),
            ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ] {
            ensure_safe_token(label, value)?;
        }
        Ok(config)
    }
}

fn verify_sudo(identity: &Path, known_hosts: &Path, host: &str) -> Result<(), String> {
    live_lab_support::verify_sudo(identity, known_hosts, host)
}

fn validate_identity(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing ssh identity file: {}", path.display()));
    }
    if path.is_symlink() {
        return Err(format!(
            "ssh identity file must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn install_assignment_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    assignment_pub_local: &Path,
    assignment_bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        assignment_pub_local,
        target,
        "/tmp/rn-assignment.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        assignment_bundle_local,
        target,
        "/tmp/rn-assignment.bundle",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub && install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment && rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rn-assignment.pub /tmp/rn-assignment.bundle",
    )
}

fn capture_root_file_to_local(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let body = capture_root(
        identity,
        known_hosts,
        target,
        format!("cat {}", shell_quote(remote_path)).as_str(),
    )?;
    write_file(local_path, &body)
}

fn install_assignment_refresh_env(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    env_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        env_local,
        target,
        "/tmp/rn-assignment-refresh.env",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0600 -o root -g root /tmp/rn-assignment-refresh.env /etc/rustynet/assignment-refresh.env && rm -f /tmp/rn-assignment-refresh.env",
    )
}

fn install_traversal_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    traversal_pub_local: &Path,
    traversal_bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        traversal_pub_local,
        target,
        "/tmp/rn-traversal.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        traversal_bundle_local,
        target,
        "/tmp/rn-traversal.bundle",
    )?;
    // Retried like the dns-zone installer alongside it. This runs inside the
    // quiesce window, where a transient SSH failure would abort the swap and force
    // the fence's error-path restore — so the flakiest step in that window is the
    // one most worth retrying.
    retry_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
        3,
        5,
    )?;
    retry_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle",
        3,
        5,
    )
}

fn install_dns_zone_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    dns_zone_pub_local: &Path,
    dns_zone_bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        dns_zone_pub_local,
        target,
        "/tmp/rn-dns-zone.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        dns_zone_bundle_local,
        target,
        "/tmp/rn-dns-zone.bundle",
    )?;
    // Use retry_root for the install commands: the soak drives rapid rustynetd restarts on
    // the same hosts immediately before this stage, which can cause transient SSH status 255
    // (connection-level failure) if the daemon restart briefly disrupts host networking.
    retry_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
        3,
        5,
    )?;
    retry_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-dns-zone.pub /etc/rustynet/dns-zone.pub && install -m 0640 -o root -g rustynetd /tmp/rn-dns-zone.bundle /var/lib/rustynet/rustynetd.dns-zone && rm -f /var/lib/rustynet/rustynetd.dns-zone.watermark /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle",
        3,
        5,
    )
}

fn issue_dns_zone_bundles_from_env(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), String> {
    scp_to(identity, known_hosts, env_local, target, remote_env_path)?;
    let command = format!(
        "sudo -n {} ops e2e-issue-dns-zone-bundles-from-env --env-file {}",
        live_lab_support::REMOTE_RUSTYNET_BIN,
        shell_quote(remote_env_path)
    );
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if !status.success() {
        let _ = run_root(
            identity,
            known_hosts,
            target,
            &format!("rm -f {}", shell_quote(remote_env_path)),
        );
        return Err(format!(
            "issue dns zone bundles from env failed for {target} with status {}",
            status_code(status)
        ));
    }
    run_root(
        identity,
        known_hosts,
        target,
        &format!("rm -f {}", shell_quote(remote_env_path)),
    )
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn status_field(status_line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix(prefix.as_str()).map(ToString::to_string))
}

fn managed_dns_state_is_valid(status: &str) -> bool {
    status_field(status, "dns_zone_state").as_deref() == Some("valid")
        && status_field(status, "dns_zone_error").as_deref() == Some("none")
        && status_field(status, "dns_alarm_state").as_deref() == Some("ok")
}

/// Stop the periodic assignment-refresh timer *and* the daemon on `target`, so a
/// multi-artifact signed-bundle swap is atomic from the daemon's point of view.
///
/// The daemon requires exact set equality between the assignment bundle's peer
/// set and the traversal bundle's target index and fail-closes (then escalates to
/// a permanent restriction) on any mismatch, so it must not reconcile while only
/// one half of the pair has been replaced. The timer is stopped before its
/// service so the timer cannot immediately re-trigger the run we just stopped.
///
/// Deliberately a fence rather than a re-ordering: staging every artifact before
/// every install would only SHRINK the inconsistent window, while quiescing
/// ELIMINATES it (and covers the dns bundle too), so do not "fix" this by
/// re-adding issue-then-install staging.
///
/// Idempotent: `systemctl stop` on an inactive unit succeeds as a no-op.
/// Every unit name is a fixed literal — no untrusted interpolation.
fn quiesce_node_for_bundle_swap(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<(), String> {
    for unit in [
        "rustynetd-assignment-refresh.timer",
        "rustynetd-assignment-refresh.service",
        "rustynetd.service",
    ] {
        run_root(
            identity,
            known_hosts,
            target,
            &format!("systemctl stop {unit}"),
        )?;
    }
    Ok(())
}

/// Restart the periodic assignment-refresh timer after the bundle swap has
/// completed and the daemon has come back up on the consistent pair.
///
/// This restores the node to the state the stage found it in; it is not what keeps
/// the in-stage traversal state fresh (the lab bakes a 24h freshness window — see
/// the release call site), and `enforce_host` would restart the timer anyway. It
/// exists so quiesce and resume are symmetric and the fence's Drop guard has a
/// matching success path.
fn resume_assignment_refresh_timer(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        "systemctl start rustynetd-assignment-refresh.timer",
    )
}

/// RAII guard making the quiesce/resume pair exception-safe.
///
/// The swap between quiesce and resume spans a long sequence of fallible SSH
/// steps, every one of which propagates with `?`. Without this guard any of them
/// — e.g. a transient SSH failure in `install_traversal_bundle` — would abort the
/// stage leaving four guests with `rustynetd` and the refresh timer stopped *by
/// the test*. That is worse than a plain stage failure for two reasons: the
/// post-mortem then shows a daemon the test stopped, confounding exactly the
/// root-causing this fence exists to make possible; and a later stage fails on
/// "rustynetd-assignment-refresh.timer is active" for a reason unrelated to what
/// it is checking.
///
/// So restoration is unconditional. On the error path (`drop` without `release`)
/// the daemon is restarted as well as the timer — a node whose daemon is running
/// and fail-closing on an inconsistent bundle pair is honestly diagnosable from
/// its own journal, whereas a node left with no daemon at all is not.
struct BundleSwapFence {
    identity: PathBuf,
    known_hosts: PathBuf,
    hosts: Vec<String>,
    released: bool,
}

impl BundleSwapFence {
    /// Stop the refresh timer + daemon on every host, returning the guard that
    /// will restore them.
    fn quiesce(identity: &Path, known_hosts: &Path, hosts: &[&str]) -> Result<Self, String> {
        let guard = Self {
            identity: identity.to_path_buf(),
            known_hosts: known_hosts.to_path_buf(),
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            released: false,
        };
        // Constructed before the loop so that a failure part-way through still
        // restores the hosts already quiesced when the guard drops.
        for host in &guard.hosts {
            quiesce_node_for_bundle_swap(&guard.identity, &guard.known_hosts, host)?;
        }
        Ok(guard)
    }

    /// Success-path release: the daemons were already brought back up cold by
    /// `enforce_host`, so only the timers need restarting — and a failure here is
    /// surfaced rather than swallowed.
    fn release(mut self) -> Result<(), String> {
        // `released` is set only AFTER every host is resumed. Setting it first would
        // disarm the guard before doing the work, so a failure on host 2 of 4 would
        // leave hosts 3 and 4 quiesced while `Drop` no-ops — precisely the hazard this
        // guard exists to prevent. On an early return the guard is still armed, `self`
        // drops, and `Drop` restores every host (restart is idempotent: `systemctl
        // start` on a running unit succeeds as a no-op, so already-resumed hosts are
        // unharmed). Mirrors `quiesce`, which likewise constructs the guard before its
        // loop rather than after.
        for host in &self.hosts {
            resume_assignment_refresh_timer(&self.identity, &self.known_hosts, host)?;
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
            // Daemon first: the timer's ExecStartPost pokes `state refresh` via the
            // daemon socket, so it wants a running daemon to talk to.
            if let Err(err) = run_root(
                &self.identity,
                &self.known_hosts,
                host,
                "systemctl start rustynetd.service",
            ) {
                eprintln!(
                    "warning: could not restart rustynetd on {host} after an aborted bundle swap: {err}"
                );
            }
            if let Err(err) =
                resume_assignment_refresh_timer(&self.identity, &self.known_hosts, host)
            {
                eprintln!(
                    "warning: could not restart rustynetd-assignment-refresh.timer on {host} after an aborted bundle swap: {err}"
                );
            }
        }
    }
}

fn refresh_signed_state(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {} state refresh",
            live_lab_support::REMOTE_RUSTYNET_BIN
        ),
    )
}

fn refresh_trust_evidence(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        &format!(
            "{} ops refresh-signed-trust",
            live_lab_support::REMOTE_RUSTYNET_BIN
        ),
    )
}

fn two_hop_runtime_ready(
    config: &Config,
    client_status: &str,
    entry_status: &str,
    final_exit_status: &str,
    second_client_status: &str,
    client_route: &str,
    second_client_route: &str,
) -> bool {
    client_status.contains(&format!("exit_node={}", config.entry_node_id))
        && client_status.contains("state=ExitActive")
        && managed_dns_state_is_valid(client_status)
        && entry_status.contains(&format!("exit_node={}", config.final_exit_node_id))
        && entry_status.contains("serving_exit_node=true")
        && managed_dns_state_is_valid(entry_status)
        && final_exit_status.contains("serving_exit_node=true")
        && managed_dns_state_is_valid(final_exit_status)
        && second_client_status.contains(&format!("exit_node={}", config.final_exit_node_id))
        && second_client_status.contains("state=ExitActive")
        && managed_dns_state_is_valid(second_client_status)
        && route_uses_tunnel(config.platform, client_route)
        && route_uses_tunnel(config.platform, second_client_route)
}

fn peer_endpoint_summary_contains(summary: &str, node_id: &str, addr: &str, port: u16) -> bool {
    let expected = format!("{node_id}/{addr}:{port}");
    summary.split('+').any(|entry| entry == expected)
}

fn managed_peer_endpoints_include(
    summary: &str,
    error: &str,
    expected_endpoints: &[(&str, &str, u16)],
) -> bool {
    error == "none"
        && expected_endpoints.iter().all(|(node_id, addr, port)| {
            peer_endpoint_summary_contains(summary, node_id, addr, *port)
        })
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_two_hop_test --ssh-identity-file <path> [options]\n\noptions:\n  --final-exit-host <user@host>\n  --client-host <user@host>\n  --entry-host <user@host>\n  --second-client-host <user@host>\n  --final-exit-node-id <id>\n  --client-node-id <id>\n  --entry-node-id <id>\n  --second-client-node-id <id>\n  --ssh-allow-cidrs <cidrs>\n  --report-path <path>\n  --log-path <path>\n  --known-hosts <path>\n  --git-commit <sha>"
    );
}

fn utc_now_string() -> String {
    let output = std::process::Command::new("date")
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

// ─── F0.8 data-plane probe support (cross-OS, W2-B) ───────────────────────────

use live_lab_support::LiveLabPlatform;

/// Public ICMP target for the end-to-end reachability probe. The client's only
/// route to it is the mesh tunnel default route (asserted as a precondition), so
/// a returning echo reply can only mean the datagram traversed the entire
/// client → entry → final_exit → internet chain and came back. Matches the
/// public address already used by the route precondition and the exit-handoff
/// data-plane ping, so we observe the same path.
const TWO_HOP_PUBLIC_PROBE_TARGET: &str = "1.1.1.1";

/// The CGNAT range the mesh assigns tunnel addresses from
/// (`mesh_cidr=100.64.0.0/10`, see daemon membership bundles). Used to pick the
/// mesh tunnel address out of the per-OS interface-address listing.
const MESH_CIDR_PREFIX: &str = "100.";

/// Logical tunnel interface name used on Linux (kernel TUN) and Windows
/// (wintun adapter alias). On macOS the WireGuard tunnel materialises as a
/// kernel-assigned `utunN` device, so the mesh address must be located by
/// scanning interface output for the CGNAT range rather than by a fixed name.
const TUNNEL_IFACE: &str = "rustynet0";

/// macOS reserves the `utun` device-name family for its WireGuard tunnels.
/// `route -n get` prints `interface: utunN` and `ifconfig utunN` carries the
/// mesh `inet 100.x` address, so the macOS route-via-tunnel predicate keys on
/// this prefix instead of `rustynet0` (which never appears as a kernel device
/// on macOS).
const MACOS_TUNNEL_IFACE_PREFIX: &str = "utun";

/// Expected reply-TTL decrement between the single-hop baseline (client -> entry
/// mesh IP, answered by the entry itself) and the two-hop path (client ->
/// final-exit mesh IP, answered by the final exit via the entry's forwarding
/// hairpin).
///
/// WireGuard is an encapsulating *link*, not a router: encapsulation does not
/// decrement the inner TTL — only *forwarding* does — and a node that
/// ORIGINATES a packet, including an ICMP echo *reply*, stamps the initial TTL
/// (64 on Linux). So the TTL observed at the client is 64 minus the number of
/// forwarding hops on the REPLY path alone; decrements on the request path are
/// invisible, because the reply is a new packet with a fresh TTL.
///
///   * baseline — the entry originates the reply and the client is a direct
///     peer: 0 forwards on the reply path -> TTL 64.
///   * two-hop  — the final exit originates the reply, addressed to the entry
///     (the entry masqueraded the hairpinned request, `phase10.rs:2285-2299`);
///     the entry un-NATs it and forwards it to the client: exactly 1 forward
///     -> TTL 63.
///
/// Hence a decrement of exactly 1.
///
/// This constant was `2` from its introduction in `b162be02` (2026-06-25) until
/// 2026-07-25. That value is unreachable in this topology: it requires TWO
/// intermediate forwarders on the reply path and there is only one (the entry)
/// — the final exit *originates* the reply rather than forwarding it. The
/// original rationale ("the entry relays the request out and the reply back, so
/// the reply loses two extra TTL units") double-counted the request-path
/// decrement, which the reply's fresh TTL cannot carry. The assertion was
/// additionally unsatisfiable in practice because `client|final_exit` was in the
/// test's ALLOW spec, making the "two-hop" probe a direct one-hop reply. See
/// `documents/operations/active/NodeEngineFlipDispositions_2026-07-24.md` D1 for
/// the full derivation, which was written down and pre-registered BEFORE the
/// verifying measurement.
///
/// The comparison against this value stays EXACT (`==`) — an exact oracle is
/// the strength of this proof; a range or threshold would weaken it.
const EXPECTED_PER_HOP_TTL_DECREMENT: i32 = 1;

/// The baseline probe is answered by the entry itself across a direct peer link,
/// so it must show an UNDECREMENTED reply.
///
/// Asserting the absolute baseline — not just the delta — is what makes the
/// derivation above binding. A delta check alone accepts `(63, 62)` exactly as it
/// accepts `(64, 63)`, even though a baseline of 63 would mean the client's reply
/// from the entry crossed a forwarding hop that the topology does not contain, i.e.
/// the model is wrong somewhere. Measured live at 64 on 2026-07-25, and at 64 in
/// both `c66887a8c` archives, so this is an observed invariant rather than a guess.
const EXPECTED_BASELINE_REPLY_TTL: u8 = 64;

/// Outcome of the end-to-end ICMP reachability probe. `attempted` records that
/// the probe actually ran (fail-closed discipline: a never-run probe is NOT a
/// pass).
struct EndToEndProbe {
    attempted: bool,
    reachable: bool,
}

/// How long to wait for the two-hop path to start carrying traffic before
/// measuring it, and how often to re-test. Bounded so a genuinely broken path
/// still fails the stage promptly rather than hanging it.
const TWO_HOP_READY_TIMEOUT_SECS: u64 = 90;
const TWO_HOP_READY_POLL_SECS: u64 = 5;

/// Outcome of the bounded readiness wait. Recorded in the report so a RED can be
/// read as "still broken after N attempts over T seconds" rather than possibly
/// "measured too early".
struct TwoHopReadiness {
    attempted: bool,
    became_reachable: bool,
    attempts: u32,
    waited_secs: u64,
}

impl TwoHopReadiness {
    fn not_attempted() -> Self {
        Self {
            attempted: false,
            became_reachable: false,
            attempts: 0,
            waited_secs: 0,
        }
    }
}

/// Bounded, fail-closed wait for the two-hop path to carry traffic.
///
/// The atomicity fence cold-restarts every chain daemon, so every tunnel must
/// re-handshake before the two-hop path works at all. Measuring a single shot
/// immediately after that races the dataplane, and a "no reply" result then cannot
/// be distinguished from a real forwarding failure — exactly the ambiguity that
/// cost a diagnostic cycle on 2026-07-25, when the baseline answered at TTL 64
/// while the final exit's mesh IP gave no reply roughly ten seconds after the
/// entry's cold restart.
///
/// Reachability is tested with a real ICMP round trip, deliberately NOT with a
/// status field: `path_live_proven` is structurally unsatisfiable on
/// shared-transport nodes (the shared userspace socket cannot observe per-peer
/// handshakes), so it must never be used as a liveness gate.
///
/// It does not weaken the *correctness* oracle: if the path never becomes reachable
/// the probes below still run and still fail, and the evidence records that the
/// failure persisted across every attempt, which is what makes the RED trustworthy.
///
/// But it is NOT free, and an earlier version of this comment overclaimed by saying
/// it "never softens" the assertion. Two availability-oracle losses, both accepted
/// deliberately:
///   * **A timing oracle is relaxed.** Previously the stage implicitly asserted the
///     path worked *immediately* after the preceding step; now it asserts only that
///     the path works *some time within 90s*. `became_reachable` and `waited_secs`
///     are recorded in the report but never asserted, so a path that only ever comes
///     up after 60s reads as a pass. Read those fields — a large `waited_secs` is its
///     own finding, not a clean result.
///   * **Warm-up masking.** The wait emits up to 42 echo requests before the real
///     measurement, priming conntrack state and WireGuard handshakes. A genuine
///     first-packet or NAT-setup defect would therefore be hidden from the probes
///     that follow.
/// Neither is a fail-closed weakening — a broken path still fails — but both trade
/// sensitivity for stability, and that trade should be visible here.
fn await_two_hop_path_ready(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    target: &str,
    platform: LiveLabPlatform,
    logger: &mut Logger,
) -> Result<TwoHopReadiness, String> {
    // MONOTONIC, deliberately: `unix_now()` is `SystemTime::now()`, and this stage runs
    // in a lab that force-syncs guest clocks. A backwards wall-clock step would collapse
    // the elapsed figure toward zero and the bound would never trip, hanging the stage on
    // a genuinely dead path. `Instant` cannot step backwards.
    let start = std::time::Instant::now();
    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        let probe = probe_end_to_end_reachability(identity, known_hosts, host, target, platform);
        let waited = start.elapsed().as_secs();
        if probe.attempted && probe.reachable {
            logger.line(
                format!(
                    "[two-hop] two-hop path became reachable after {attempts} attempt(s), {waited}s"
                )
                .as_str(),
            )?;
            return Ok(TwoHopReadiness {
                attempted: true,
                became_reachable: true,
                attempts,
                waited_secs: waited,
            });
        }
        if waited >= TWO_HOP_READY_TIMEOUT_SECS {
            logger.line(
                format!(
                    "[two-hop] two-hop path NOT reachable after {attempts} attempt(s) over {waited}s (limit {TWO_HOP_READY_TIMEOUT_SECS}s); measuring anyway so the probes below fail closed"
                )
                .as_str(),
            )?;
            return Ok(TwoHopReadiness {
                attempted: true,
                became_reachable: false,
                attempts,
                waited_secs: waited,
            });
        }
        std::thread::sleep(std::time::Duration::from_secs(TWO_HOP_READY_POLL_SECS));
    }
}

/// Outcome of a single reply-TTL measurement. `attempted` is false when the
/// probe could not run at all (e.g. the mesh IP was never discovered) or
/// produced no parseable TTL — those MUST NOT be read as a clean result.
struct TtlProbe {
    attempted: bool,
    ttl: Option<u8>,
}

impl TtlProbe {
    fn not_attempted() -> Self {
        Self {
            attempted: false,
            ttl: None,
        }
    }
}

/// Aggregated verdict for the two F0.8 behavioural assertions plus the measured
/// TTL delta carried into the report.
struct TwoHopDataplaneProof {
    end_to_end_reachable: bool,
    per_hop_ttl_decrement: Option<i32>,
    per_hop_ttl_decrement_ok: bool,
}

impl TwoHopDataplaneProof {
    fn summary_line(&self) -> String {
        format!(
            "end_to_end_reachable={} per_hop_ttl_decrement={} per_hop_ttl_decrement_ok={}",
            self.end_to_end_reachable,
            self.per_hop_ttl_decrement
                .map_or_else(|| "none".to_owned(), |delta| delta.to_string()),
            self.per_hop_ttl_decrement_ok
        )
    }
}

/// Pure verdict: combine the end-to-end and per-hop probes into the two
/// behavioural pass/fail facts. Fail-closed throughout:
///   - end-to-end passes only if it was attempted AND a reply returned;
///   - per-hop passes only if BOTH TTL probes were attempted, BOTH parsed a
///     TTL, and the baseline−two_hop delta is exactly the expected decrement.
///
/// A missing/unattempted probe yields `None`/`false`, never a silent pass.
fn evaluate_two_hop_dataplane_proof(
    end_to_end: &EndToEndProbe,
    baseline_ttl: &TtlProbe,
    two_hop_ttl: &TtlProbe,
) -> TwoHopDataplaneProof {
    let end_to_end_reachable = end_to_end.attempted && end_to_end.reachable;
    let per_hop_ttl_decrement = compute_ttl_decrement(baseline_ttl, two_hop_ttl);
    // Both conditions are required: the exact delta AND the absolute baseline. See
    // EXPECTED_BASELINE_REPLY_TTL for why the delta alone is not a sufficient oracle.
    let per_hop_ttl_decrement_ok = per_hop_ttl_decrement == Some(EXPECTED_PER_HOP_TTL_DECREMENT)
        && baseline_ttl.ttl == Some(EXPECTED_BASELINE_REPLY_TTL);
    TwoHopDataplaneProof {
        end_to_end_reachable,
        per_hop_ttl_decrement,
        per_hop_ttl_decrement_ok,
    }
}

/// `baseline_ttl − two_hop_ttl`, but only when both probes were attempted and
/// both parsed a TTL. Returns `None` (fail-closed) otherwise.
fn compute_ttl_decrement(baseline_ttl: &TtlProbe, two_hop_ttl: &TtlProbe) -> Option<i32> {
    if !baseline_ttl.attempted || !two_hop_ttl.attempted {
        return None;
    }
    let baseline = baseline_ttl.ttl?;
    let two_hop = two_hop_ttl.ttl?;
    Some(i32::from(baseline) - i32::from(two_hop))
}

/// Build the per-OS command that lists the mesh tunnel's IPv4 address(es).
/// Argv-only via `capture_root` (POSIX) or PowerShell; the command is a fixed
/// literal with no untrusted interpolation. The result is fed to the matching
/// per-OS parser.
///
///   * Linux — `ip -4 -o addr show dev rustynet0` (kernel TUN named rustynet0).
///   * macOS — `ifconfig` (full dump): the tunnel is a kernel-assigned `utunN`
///     device, not a fixed name, so we scan every interface for the CGNAT
///     `inet 100.x` address. `ipconfig getifaddr` needs a known device name we
///     do not have, so `ifconfig` is the portable choice.
///   * Windows — `Get-NetIPAddress -InterfaceAlias rustynet0` (the wintun
///     adapter alias, per `windows_tunnel_smoke.rs` default `rustynet0`).
fn mesh_ipv4_discovery_command(platform: LiveLabPlatform) -> String {
    match platform {
        LiveLabPlatform::Linux => {
            format!("ip -4 -o addr show dev {TUNNEL_IFACE} 2>/dev/null || true")
        }
        // REVIEW (W2-B): macОS WireGuard tunnels surface as utunN; we scan the
        // whole ifconfig dump for the CGNAT mesh address rather than guessing
        // the utun index. If the mac daemon is not up as the entry/exit, no
        // 100.x line appears and the parser returns None → probe not-attempted
        // → fail-closed (honest, not a fake pass).
        LiveLabPlatform::MacOs => "/sbin/ifconfig 2>/dev/null || true".to_owned(),
        // REVIEW (W2-B): the wintun adapter alias is `rustynet0` per the
        // reviewed Windows tunnel-smoke default. Out-String -Width keeps the
        // IPAddress column from wrapping.
        LiveLabPlatform::Windows => {
            "powershell -NoProfile -Command \"Get-NetIPAddress -InterfaceAlias rustynet0 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress | Out-String -Width 32767\"".to_owned()
        }
    }
}

/// Discover the mesh (CGNAT-range) tunnel IPv4 address on `host`. Argv-only via
/// the existing `capture_root` (POSIX) / `capture_remote_stdout` (Windows
/// PowerShell) primitives. Returns `None` (not an error) when no mesh address
/// is present so the caller can record the probe as not-attempted and fail
/// closed in the evaluator rather than aborting the whole stage.
fn discover_mesh_ipv4(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    platform: LiveLabPlatform,
) -> Result<Option<String>, String> {
    let command = mesh_ipv4_discovery_command(platform);
    let raw = match platform {
        // Linux + macOS go through sudo -n sh -lc (POSIX), matching the
        // byte-identical Linux path that predates this Wave.
        LiveLabPlatform::Linux | LiveLabPlatform::MacOs => {
            capture_root(identity, known_hosts, host, command.as_str())?
        }
        // Windows OpenSSH sessions are Administrator already and have no sudo;
        // run the PowerShell command directly. A transport failure collapses
        // to empty stdout so the parser returns None (fail-closed).
        LiveLabPlatform::Windows => {
            live_lab_support::capture_remote_stdout(identity, known_hosts, host, command.as_str())
                .unwrap_or_default()
        }
    };
    Ok(parse_mesh_ipv4_for_platform(platform, &raw))
}

/// Dispatch to the per-OS mesh-address parser.
fn parse_mesh_ipv4_for_platform(platform: LiveLabPlatform, output: &str) -> Option<String> {
    match platform {
        LiveLabPlatform::Linux | LiveLabPlatform::MacOs => parse_mesh_ipv4_from_inet_tokens(output),
        LiveLabPlatform::Windows => parse_mesh_ipv4_from_windows_ipaddress(output),
    }
}

/// Parse the first mesh-range (`100.64.0.0/10`) IPv4 address out of `inet`-token
/// output. Handles BOTH:
///   * Linux `ip -4 -o addr show dev rustynet0`:
///     `4: rustynet0    inet 100.64.0.3/32 scope global rustynet0\  valid_lft ...`
///   * macOS `ifconfig` (full dump):
///     `utun4: flags=...\n\tinet 100.64.0.3 --> 100.64.0.3 netmask 0xffffffff`
///
/// In both, the address follows an `inet` token; we strip any `/prefix` (Linux)
/// and accept the bare dotted-quad (macOS). Returns `None` if no `inet 100.x`
/// token is present.
fn parse_mesh_ipv4_from_inet_tokens(output: &str) -> Option<String> {
    let mut tokens = output.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if token != "inet" {
            continue;
        }
        if let Some(addr_with_prefix) = tokens.peek() {
            let addr = addr_with_prefix
                .split('/')
                .next()
                .unwrap_or(addr_with_prefix);
            if addr.starts_with(MESH_CIDR_PREFIX) && addr.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(addr.to_owned());
            }
        }
    }
    None
}

/// Parse the mesh-range IPv4 address from Windows
/// `Get-NetIPAddress ... | Select -ExpandProperty IPAddress` output, which is a
/// bare list of dotted-quad addresses (one per line), e.g. `100.64.0.3`.
/// Returns the first address in the CGNAT mesh range, or `None`.
fn parse_mesh_ipv4_from_windows_ipaddress(output: &str) -> Option<String> {
    output.split_whitespace().find_map(|token| {
        if token.starts_with(MESH_CIDR_PREFIX) && token.parse::<std::net::Ipv4Addr>().is_ok() {
            Some(token.to_owned())
        } else {
            None
        }
    })
}

/// Build the per-OS end-to-end reachability ping command (success/fail only;
/// stdout discarded). `target` is shell/PowerShell quoted by the caller's
/// transport. The trailing `|| true` / `try`/`catch` semantics are NOT used
/// here — we depend on the command's EXIT STATUS, so the command must propagate
/// ping's own success/failure.
///
///   * Linux  — `ping -c 3 -W 2 <t>` (iputils: `-W` is seconds).
///   * macOS  — `ping -c 3 -t 5 <t>` (BSD ping has no `-W` reply-timeout flag;
///     `-t` is the overall deadline in seconds).
///   * Windows— `ping -n 3 -w 2000 <t>` (`-n` count, `-w` per-reply timeout in
///     MILLIseconds). `ping.exe` exits non-zero when every echo is lost.
fn reachability_ping_command(platform: LiveLabPlatform, target: &str) -> String {
    match platform {
        LiveLabPlatform::Linux => {
            format!("ping -c 3 -W 2 {} >/dev/null 2>&1", shell_quote(target))
        }
        LiveLabPlatform::MacOs => {
            format!("ping -c 3 -t 5 {} >/dev/null 2>&1", shell_quote(target))
        }
        // ping.exe's exit code is reliable; we don't wrap in try/catch so the
        // non-zero exit on total loss propagates to ssh_status.
        LiveLabPlatform::Windows => {
            format!("ping -n 3 -w 2000 {}", windows_ping_quote(target))
        }
    }
}

/// Build the per-OS reply-TTL ping command. Unlike the reachability probe this
/// CAPTURES stdout (so the per-OS TTL field can be parsed), and tolerates a
/// non-zero exit (a single dropped echo still prints a parseable reply line).
///
///   * Linux  — `ping -c 3 -W 2 <t> 2>&1 || true` (iputils `ttl=`).
///   * macOS  — `ping -c 3 -t 5 <t> 2>&1 || true` (BSD `ttl=`).
///   * Windows— `ping -n 3 -w 2000 <t>` (uppercase `TTL=`).
fn reply_ttl_ping_command(platform: LiveLabPlatform, target: &str) -> String {
    match platform {
        LiveLabPlatform::Linux => {
            format!("ping -c 3 -W 2 {} 2>&1 || true", shell_quote(target))
        }
        LiveLabPlatform::MacOs => {
            format!("ping -c 3 -t 5 {} 2>&1 || true", shell_quote(target))
        }
        LiveLabPlatform::Windows => {
            format!("ping -n 3 -w 2000 {}", windows_ping_quote(target))
        }
    }
}

/// Conservative double-quote wrap for a ping target passed to `ping.exe` via a
/// PowerShell/cmd-bridged OpenSSH session. The target is already validated as a
/// safe token (`ensure_safe_token` on hosts/ids; this constant target is the
/// literal `1.1.1.1`), so this is defence-in-depth, not the primary guard.
fn windows_ping_quote(target: &str) -> String {
    format!("\"{}\"", target.replace('"', ""))
}

/// End-to-end reachability probe: ping `target` from `host` through the tunnel
/// chain. Reuses the argv-only `ssh_status` ping pattern as the exit-handoff
/// data-plane monitor. A transport error or a non-zero ping exit records
/// `reachable=false`; `attempted` is true whenever the ping command was
/// dispatched (we always dispatch it here, fail-closed discipline preserved).
fn probe_end_to_end_reachability(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    target: &str,
    platform: LiveLabPlatform,
) -> EndToEndProbe {
    let command = reachability_ping_command(platform, target);
    let reachable = matches!(
        ssh_status(identity, known_hosts, host, &command),
        Ok(status) if status.success()
    );
    EndToEndProbe {
        attempted: true,
        reachable,
    }
}

/// Measure the reply TTL the client observes when pinging `target`. Uses the
/// argv-only capture primitive and parses the per-OS TTL field from the reply.
/// A probe that produces no parseable TTL is recorded `attempted=true,
/// ttl=None`, which the evaluator treats as a fail (cannot prove the per-hop
/// delta). A transport failure is recorded as not-attempted (also a fail).
fn probe_reply_ttl(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    target: &str,
    platform: LiveLabPlatform,
) -> TtlProbe {
    let command = reply_ttl_ping_command(platform, target);
    let captured = match platform {
        LiveLabPlatform::Linux | LiveLabPlatform::MacOs => {
            capture_root(identity, known_hosts, host, &command)
        }
        LiveLabPlatform::Windows => {
            live_lab_support::capture_remote_stdout(identity, known_hosts, host, &command)
        }
    };
    match captured {
        Ok(output) => TtlProbe {
            attempted: true,
            ttl: parse_reply_ttl_for_platform(platform, &output),
        },
        // A transport failure means the probe did not produce a measurement.
        Err(_) => TtlProbe::not_attempted(),
    }
}

/// Dispatch to the per-OS reply-TTL parser. The TTL field casing differs by
/// platform (iputils/BSD lowercase `ttl=` vs Windows uppercase `TTL=`); the
/// TTL−2 decrement arithmetic downstream is identical regardless of OS.
fn parse_reply_ttl_for_platform(platform: LiveLabPlatform, output: &str) -> Option<u8> {
    match platform {
        // Linux iputils and macOS BSD ping both print a lowercase `ttl=` field
        // in the reply line, so they share one tolerant parser.
        LiveLabPlatform::Linux | LiveLabPlatform::MacOs => parse_ping_reply_ttl_posix(output),
        LiveLabPlatform::Windows => parse_ping_reply_ttl_windows(output),
    }
}

/// Parse the reply TTL from POSIX `ping` stdout (Linux iputils + macOS BSD).
/// Both print the TTL as a lowercase `ttl=<n>` token in the reply line:
///   Linux: `64 bytes from 100.64.0.3: icmp_seq=1 ttl=63 time=0.40 ms`
///   macOS: `64 bytes from 100.64.0.3: icmp_seq=0 ttl=63 time=0.412 ms`
/// Returns the first parseable value, or `None` if absent (all echoes lost, so
/// no reply line was printed).
fn parse_ping_reply_ttl_posix(output: &str) -> Option<u8> {
    for token in output.split_whitespace() {
        if let Some(value) = token.strip_prefix("ttl=")
            && let Ok(ttl) = value.parse::<u8>()
        {
            return Some(ttl);
        }
    }
    None
}

/// Parse the reply TTL from Windows `ping.exe` stdout. Windows prints an
/// uppercase `TTL=` field embedded in the reply line with no surrounding
/// whitespace:
///   `Reply from 100.64.0.3: bytes=32 time=1ms TTL=63`
/// Because `TTL=63` may be glued to the preceding token, we search each
/// whitespace token for a `TTL=` substring rather than requiring a prefix.
/// Returns the first parseable value, or `None` (request-timed-out lines carry
/// no `TTL=`).
fn parse_ping_reply_ttl_windows(output: &str) -> Option<u8> {
    for token in output.split_whitespace() {
        if let Some(idx) = token.find("TTL=") {
            let value: String = token[idx + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(ttl) = value.parse::<u8>() {
                return Some(ttl);
            }
        }
    }
    None
}

/// Build the per-OS command that resolves the route to `target` (the
/// default-route precondition: the client's traffic to a public target must
/// egress via the mesh tunnel, never the LAN gateway).
///
///   * Linux  — `ip -4 route get <t>` (output contains `dev rustynet0`).
///   * macOS  — `route -n get <t>` (output contains `interface: utunN`).
///   * Windows— `Find-NetRoute -RemoteIPAddress <t>` then read InterfaceAlias
///     (the wintun adapter alias is `rustynet0`).
fn default_route_probe_command(platform: LiveLabPlatform, target: &str) -> String {
    match platform {
        LiveLabPlatform::Linux => format!("ip -4 route get {} || true", shell_quote(target)),
        LiveLabPlatform::MacOs => {
            format!("route -n get {} 2>/dev/null || true", shell_quote(target))
        }
        // Find-NetRoute returns the route the OS would actually use to reach
        // the target; we surface InterfaceAlias so the tunnel-egress predicate
        // can match the wintun adapter name. SilentlyContinue + Out-String keep
        // the row machine-parseable and unwrapped.
        LiveLabPlatform::Windows => format!(
            "powershell -NoProfile -Command \"(Find-NetRoute -RemoteIPAddress {} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias) -join ' ' | Out-String -Width 32767\"",
            windows_ping_quote(target)
        ),
    }
}

/// Per-OS predicate: does the resolved route to the public target egress via
/// the mesh tunnel interface (rather than a LAN gateway)? This is the
/// behavioural precondition that makes the end-to-end reachability proof
/// meaningful.
///
///   * Linux  — route output names `dev rustynet0`. Guard against substring
///     false-positives (`rustynet0x`) by requiring the `dev rustynet0` token
///     with a following word boundary.
///   * macOS  — route output names `interface: utunN`; match the `utun`
///     device-name prefix.
///   * Windows— Find-NetRoute InterfaceAlias is the wintun adapter `rustynet0`.
fn route_uses_tunnel(platform: LiveLabPlatform, route_output: &str) -> bool {
    match platform {
        LiveLabPlatform::Linux => route_output_names_linux_tunnel_dev(route_output),
        LiveLabPlatform::MacOs => route_output_names_macos_utun_interface(route_output),
        LiveLabPlatform::Windows => route_output_names_windows_tunnel_alias(route_output),
    }
}

/// Linux `ip route get` egresses the tunnel when the output names
/// `dev rustynet0`. Require the device token to be followed by whitespace or
/// end-of-string so `dev rustynet0x` / `dev rustynet01` do NOT match.
fn route_output_names_linux_tunnel_dev(route_output: &str) -> bool {
    let needle = format!("dev {TUNNEL_IFACE}");
    route_output.match_indices(needle.as_str()).any(|(idx, _)| {
        let after = &route_output[idx + needle.len()..];
        after
            .chars()
            .next()
            .map(|c| c.is_whitespace())
            .unwrap_or(true)
    })
}

/// macOS `route -n get` egresses the tunnel when the `interface:` line names a
/// `utunN` device. Match the `interface:` key then the `utun` device-name
/// prefix so a non-tunnel egress (`interface: en0`) does NOT satisfy the check.
fn route_output_names_macos_utun_interface(route_output: &str) -> bool {
    route_output.lines().any(|line| {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            rest.trim().starts_with(MACOS_TUNNEL_IFACE_PREFIX)
        } else {
            false
        }
    })
}

/// Windows `Find-NetRoute` egresses the tunnel when the resolved InterfaceAlias
/// is the wintun adapter `rustynet0`. Match the alias as a whitespace-delimited
/// token so `rustynet0x` cannot satisfy the check.
fn route_output_names_windows_tunnel_alias(route_output: &str) -> bool {
    route_output
        .split_whitespace()
        .any(|token| token == TUNNEL_IFACE)
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_field_extracts_managed_peer_endpoints() {
        let status = "node_id=client-2 managed_peer_endpoints=client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820 managed_peer_endpoints_error=none";
        assert_eq!(
            super::status_field(status, "managed_peer_endpoints"),
            Some("client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820".to_owned())
        );
        assert_eq!(
            super::status_field(status, "managed_peer_endpoints_error"),
            Some("none".to_owned())
        );
    }

    #[test]
    fn peer_endpoint_summary_contains_expected_endpoint() {
        let summary = "client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820";
        assert!(super::peer_endpoint_summary_contains(
            summary,
            "client-1",
            "192.168.64.24",
            51820
        ));
        assert!(super::peer_endpoint_summary_contains(
            summary,
            "exit-1",
            "192.168.64.22",
            51820
        ));
        assert!(!super::peer_endpoint_summary_contains(
            summary,
            "client-4",
            "192.168.64.25",
            51820
        ));
    }

    #[test]
    fn managed_peer_endpoints_include_requires_none_error_and_all_expected_endpoints() {
        let summary = "client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820";
        assert!(super::managed_peer_endpoints_include(
            summary,
            "none",
            &[
                ("client-1", "192.168.64.24", 51820),
                ("exit-1", "192.168.64.22", 51820)
            ]
        ));
        assert!(!super::managed_peer_endpoints_include(
            summary,
            "backend_unavailable",
            &[
                ("client-1", "192.168.64.24", 51820),
                ("exit-1", "192.168.64.22", 51820)
            ]
        ));
        assert!(!super::managed_peer_endpoints_include(
            summary,
            "none",
            &[
                ("client-1", "192.168.64.24", 51820),
                ("client-4", "192.168.64.25", 51820)
            ]
        ));
    }

    #[test]
    fn managed_dns_state_is_valid_requires_valid_none_ok() {
        assert!(super::managed_dns_state_is_valid(
            "dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok"
        ));
        assert!(!super::managed_dns_state_is_valid(
            "dns_zone_state=invalid dns_zone_error=dns_zone_bundle_is_stale dns_alarm_state=error"
        ));
        assert!(!super::managed_dns_state_is_valid(
            "dns_zone_state=valid dns_zone_error=none dns_alarm_state=error"
        ));
    }

    #[test]
    fn two_hop_source_raises_the_swap_fence_before_the_first_bundle_install() {
        // The daemon requires EXACT set equality between the assignment bundle's peer
        // set and the traversal bundle's target index, failing closed in both
        // directions and latching a permanent restriction after five rejections. So no
        // reconcile may observe a half-swapped pair, and the ordering that guarantees
        // it must be pinned by a test rather than only by a green live run: revert or
        // reorder the fence and the live suite would simply go red again for reasons
        // that take a 40-minute run to diagnose. Mirrors the exit_handoff test that
        // pins trust-refresh-before-state-refresh the same way.
        let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bin/live_linux_two_hop_test.rs");
        let source =
            std::fs::read_to_string(&source_path).expect("two-hop source should be readable");
        let quiesce_idx = source
            .find("BundleSwapFence::quiesce(")
            .expect("source should quiesce the chain nodes before swapping signed bundle halves");
        let first_install_idx = source
            .find("install_assignment_bundle(")
            .expect("source should install assignment bundles");
        let traversal_install_idx = source
            .find("install_traversal_bundle(")
            .expect("source should install traversal bundles");
        let release_idx = source
            .find("swap_fence.release()")
            .expect("source should release the fence after both halves are installed");
        assert!(
            quiesce_idx < first_install_idx,
            "the fence must be raised BEFORE the first signed-bundle install, or a \
             reconcile can observe the narrowed assignment against the stale full-mesh \
             traversal index and tear the tunnel down"
        );
        assert!(
            traversal_install_idx < release_idx,
            "the fence must not be released until the traversal half is installed too"
        );
    }

    #[test]
    fn two_hop_runtime_ready_requires_expected_exit_chain_and_routes() {
        let config = super::Config {
            platform: super::live_lab_support::LiveLabPlatform::Linux,
            ssh_identity_file: std::path::PathBuf::from("/tmp/key"),
            final_exit_host: "debian@192.168.64.22".to_owned(),
            client_host: "debian@192.168.64.24".to_owned(),
            entry_host: "debian@192.168.64.26".to_owned(),
            second_client_host: "debian@192.168.64.29".to_owned(),
            final_exit_node_id: "exit-1".to_owned(),
            client_node_id: "client-1".to_owned(),
            entry_node_id: "client-2".to_owned(),
            second_client_node_id: "client-4".to_owned(),
            ssh_allow_cidrs: "192.168.64.0/24".to_owned(),
            report_path: std::path::PathBuf::from("/tmp/report.json"),
            log_path: std::path::PathBuf::from("/tmp/report.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
        };

        assert!(super::two_hop_runtime_ready(
            &config,
            "node_role=client state=ExitActive exit_node=client-2 dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=admin state=ExitActive exit_node=exit-1 serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=admin state=ExitActive serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=client state=ExitActive exit_node=exit-1 dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "1.1.1.1 dev rustynet0",
            "1.1.1.1 dev rustynet0",
        ));
        assert!(!super::two_hop_runtime_ready(
            &config,
            "node_role=client state=ExitActive exit_node=client-2 dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=admin state=ExitActive exit_node=exit-1 serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=admin state=ExitActive serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=client state=ExitActive exit_node=exit-1 dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "1.1.1.1 dev rustynet0",
            "1.1.1.1 via 192.168.64.1 dev enp0s1",
        ));
        assert!(!super::two_hop_runtime_ready(
            &config,
            "node_role=client state=ExitActive exit_node=client-2 dns_zone_state=invalid dns_zone_error=dns_zone_bundle_is_stale dns_alarm_state=error",
            "node_role=admin state=ExitActive exit_node=exit-1 serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=admin state=ExitActive serving_exit_node=true dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "node_role=client state=ExitActive exit_node=exit-1 dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            "1.1.1.1 dev rustynet0",
            "1.1.1.1 dev rustynet0",
        ));
    }

    use super::LiveLabPlatform;

    // ─── POSIX (Linux iputils) reply-TTL parser ──────────────────────────────
    #[test]
    fn parse_ping_reply_ttl_posix_reads_iputils_reply_line() {
        let out = "PING 100.64.0.3 (100.64.0.3) 56(84) bytes of data.\n\
                   64 bytes from 100.64.0.3: icmp_seq=1 ttl=63 time=0.40 ms\n";
        assert_eq!(super::parse_ping_reply_ttl_posix(out), Some(63));
    }

    // ─── POSIX (macOS BSD) reply-TTL parser (same lowercase ttl= field) ───────
    #[test]
    fn parse_ping_reply_ttl_posix_reads_bsd_macos_reply_line() {
        // Realistic macOS BSD ping output: icmp_seq starts at 0, time has more
        // decimal places; the TTL field is still lowercase `ttl=`.
        let out = "PING 100.64.0.3 (100.64.0.3): 56 data bytes\n\
                   64 bytes from 100.64.0.3: icmp_seq=0 ttl=63 time=0.412 ms\n";
        assert_eq!(super::parse_ping_reply_ttl_posix(out), Some(63));
    }

    #[test]
    fn parse_ping_reply_ttl_posix_returns_none_when_all_requests_time_out() {
        let out = "PING 100.64.0.5 (100.64.0.5) 56(84) bytes of data.\n\n\
                   --- 100.64.0.5 ping statistics ---\n\
                   3 packets transmitted, 0 received, 100% packet loss, time 2043ms\n";
        assert_eq!(super::parse_ping_reply_ttl_posix(out), None);
    }

    // ─── Windows ping.exe reply-TTL parser (uppercase glued TTL=) ─────────────
    #[test]
    fn parse_ping_reply_ttl_windows_reads_uppercase_glued_ttl() {
        // Realistic Windows ping.exe output: TTL is uppercase and glued to the
        // preceding token with no whitespace.
        let out = "Pinging 100.64.0.3 with 32 bytes of data:\r\n\
                   Reply from 100.64.0.3: bytes=32 time=1ms TTL=63\r\n";
        assert_eq!(super::parse_ping_reply_ttl_windows(out), Some(63));
    }

    #[test]
    fn parse_ping_reply_ttl_windows_returns_none_on_timeout() {
        let out = "Pinging 100.64.0.5 with 32 bytes of data:\r\n\
                   Request timed out.\r\n\
                   Request timed out.\r\n\
                   Ping statistics for 100.64.0.5:\r\n\
                   Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),\r\n";
        assert_eq!(super::parse_ping_reply_ttl_windows(out), None);
    }

    #[test]
    fn parse_ping_reply_ttl_windows_does_not_match_posix_lowercase() {
        // A POSIX lowercase `ttl=` line must NOT satisfy the Windows parser
        // (the platform dispatcher keeps them separate, but assert the guard).
        let out = "64 bytes from 100.64.0.3: icmp_seq=1 ttl=63 time=0.40 ms";
        assert_eq!(super::parse_ping_reply_ttl_windows(out), None);
    }

    // The TTL−2 decrement arithmetic is identical regardless of OS once a TTL
    // is parsed; verify the per-OS dispatcher routes to the right parser.
    #[test]
    fn parse_reply_ttl_for_platform_dispatches_per_os() {
        let posix = "64 bytes from 100.64.0.3: icmp_seq=1 ttl=61 time=0.40 ms";
        let windows = "Reply from 100.64.0.3: bytes=32 time=1ms TTL=61";
        assert_eq!(
            super::parse_reply_ttl_for_platform(LiveLabPlatform::Linux, posix),
            Some(61)
        );
        assert_eq!(
            super::parse_reply_ttl_for_platform(LiveLabPlatform::MacOs, posix),
            Some(61)
        );
        assert_eq!(
            super::parse_reply_ttl_for_platform(LiveLabPlatform::Windows, windows),
            Some(61)
        );
    }

    // ─── Mesh-IP discovery: Linux `ip -4 -o addr` ────────────────────────────
    #[test]
    fn parse_mesh_ipv4_picks_linux_rustynet0_cgnat_address() {
        let out = "4: rustynet0    inet 100.64.0.3/32 scope global rustynet0\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(
            super::parse_mesh_ipv4_from_inet_tokens(out),
            Some("100.64.0.3".to_owned())
        );
    }

    // ─── Mesh-IP discovery: macOS `ifconfig` utun device ──────────────────────
    #[test]
    fn parse_mesh_ipv4_picks_macos_utun_cgnat_address() {
        // Realistic macOS `ifconfig` dump: the mesh address lives on a utunN
        // device as a bare dotted-quad (no /prefix), with a `-->` peer column.
        let out = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                   \tinet 192.168.18.7 netmask 0xffffff00 broadcast 192.168.18.255\n\
                   utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n\
                   \tinet 100.64.0.3 --> 100.64.0.3 netmask 0xffffffff\n";
        assert_eq!(
            super::parse_mesh_ipv4_from_inet_tokens(out),
            Some("100.64.0.3".to_owned())
        );
    }

    #[test]
    fn parse_mesh_ipv4_inet_tokens_ignores_non_mesh_addresses() {
        // A stray non-mesh inet on the device must not be mistaken for the
        // tunnel address; only the 100.x CGNAT mesh range is accepted.
        let out = "4: rustynet0    inet 192.168.18.5/24 scope global rustynet0\n";
        assert_eq!(super::parse_mesh_ipv4_from_inet_tokens(out), None);
    }

    #[test]
    fn parse_mesh_ipv4_inet_tokens_returns_none_on_empty() {
        assert_eq!(super::parse_mesh_ipv4_from_inet_tokens(""), None);
    }

    // ─── Mesh-IP discovery: Windows Get-NetIPAddress IPAddress list ───────────
    #[test]
    fn parse_mesh_ipv4_windows_picks_cgnat_address() {
        // Get-NetIPAddress -ExpandProperty IPAddress yields bare dotted-quads.
        let out = "169.254.12.5\r\n100.64.0.3\r\n";
        assert_eq!(
            super::parse_mesh_ipv4_from_windows_ipaddress(out),
            Some("100.64.0.3".to_owned())
        );
    }

    #[test]
    fn parse_mesh_ipv4_windows_returns_none_without_mesh_address() {
        let out = "192.168.18.5\r\n";
        assert_eq!(super::parse_mesh_ipv4_from_windows_ipaddress(out), None);
    }

    #[test]
    fn parse_mesh_ipv4_for_platform_dispatches_per_os() {
        let posix =
            "utun4: flags=8051 mtu 1280\n\tinet 100.64.0.7 --> 100.64.0.7 netmask 0xffffffff\n";
        let windows = "100.64.0.7\r\n";
        assert_eq!(
            super::parse_mesh_ipv4_for_platform(LiveLabPlatform::MacOs, posix),
            Some("100.64.0.7".to_owned())
        );
        assert_eq!(
            super::parse_mesh_ipv4_for_platform(LiveLabPlatform::Windows, windows),
            Some("100.64.0.7".to_owned())
        );
    }

    // ─── route-via-tunnel precondition predicate, per OS ──────────────────────
    #[test]
    fn route_uses_tunnel_linux_requires_dev_rustynet0() {
        // Realistic `ip -4 route get 1.1.1.1` egressing the tunnel.
        let via_tunnel = "1.1.1.1 dev rustynet0 src 100.64.0.3 uid 0 \n    cache";
        assert!(super::route_uses_tunnel(LiveLabPlatform::Linux, via_tunnel));
        // Egressing the LAN gateway must NOT count.
        let via_lan = "1.1.1.1 via 192.168.18.1 dev enp0s1 src 192.168.18.7 uid 0 \n    cache";
        assert!(!super::route_uses_tunnel(LiveLabPlatform::Linux, via_lan));
        // A look-alike device name (`rustynet0x`) must NOT match.
        let lookalike = "1.1.1.1 dev rustynet0x src 100.64.0.3 uid 0";
        assert!(!super::route_uses_tunnel(LiveLabPlatform::Linux, lookalike));
    }

    #[test]
    fn route_uses_tunnel_macos_requires_utun_interface() {
        // Realistic `route -n get 1.1.1.1` egressing the utun tunnel.
        let via_tunnel = "   route to: 1.1.1.1\ndestination: default\n       gateway: 100.64.0.1\n     interface: utun4\n";
        assert!(super::route_uses_tunnel(LiveLabPlatform::MacOs, via_tunnel));
        // Egressing en0 (the LAN) must NOT count.
        let via_lan = "   route to: 1.1.1.1\ndestination: default\n       gateway: 192.168.18.1\n     interface: en0\n";
        assert!(!super::route_uses_tunnel(LiveLabPlatform::MacOs, via_lan));
    }

    #[test]
    fn route_uses_tunnel_windows_requires_wintun_alias() {
        // Find-NetRoute InterfaceAlias resolved to the wintun adapter.
        let via_tunnel = "rustynet0\r\n";
        assert!(super::route_uses_tunnel(
            LiveLabPlatform::Windows,
            via_tunnel
        ));
        // Egressing the physical Ethernet alias must NOT count.
        let via_lan = "Ethernet\r\n";
        assert!(!super::route_uses_tunnel(LiveLabPlatform::Windows, via_lan));
        // A look-alike alias must NOT match.
        let lookalike = "rustynet0x\r\n";
        assert!(!super::route_uses_tunnel(
            LiveLabPlatform::Windows,
            lookalike
        ));
    }

    // ─── per-OS command shape (smoke checks of the literal builders) ──────────
    #[test]
    fn reachability_ping_command_is_per_os_correct() {
        assert!(
            super::reachability_ping_command(LiveLabPlatform::Linux, "1.1.1.1")
                .contains("-c 3 -W 2")
        );
        assert!(
            super::reachability_ping_command(LiveLabPlatform::MacOs, "1.1.1.1")
                .contains("-c 3 -t 5")
        );
        let win = super::reachability_ping_command(LiveLabPlatform::Windows, "1.1.1.1");
        assert!(win.contains("-n 3 -w 2000"));
        assert!(win.contains("\"1.1.1.1\""));
    }

    #[test]
    fn reply_ttl_ping_command_captures_per_os() {
        // POSIX paths keep `2>&1 || true` so a partial reply still prints a
        // parseable line; Windows relies on ping.exe's own stdout.
        assert!(
            super::reply_ttl_ping_command(LiveLabPlatform::Linux, "1.1.1.1")
                .contains("2>&1 || true")
        );
        assert!(
            super::reply_ttl_ping_command(LiveLabPlatform::MacOs, "1.1.1.1")
                .contains("2>&1 || true")
        );
        assert!(
            super::reply_ttl_ping_command(LiveLabPlatform::Windows, "1.1.1.1").contains("-n 3")
        );
    }

    #[test]
    fn mesh_ipv4_discovery_command_is_per_os_correct() {
        assert!(
            super::mesh_ipv4_discovery_command(LiveLabPlatform::Linux)
                .contains("ip -4 -o addr show dev rustynet0")
        );
        assert!(super::mesh_ipv4_discovery_command(LiveLabPlatform::MacOs).contains("ifconfig"));
        assert!(
            super::mesh_ipv4_discovery_command(LiveLabPlatform::Windows)
                .contains("Get-NetIPAddress -InterfaceAlias rustynet0")
        );
    }

    #[test]
    fn default_route_probe_command_is_per_os_correct() {
        assert!(
            super::default_route_probe_command(LiveLabPlatform::Linux, "1.1.1.1")
                .contains("ip -4 route get")
        );
        assert!(
            super::default_route_probe_command(LiveLabPlatform::MacOs, "1.1.1.1")
                .contains("route -n get")
        );
        assert!(
            super::default_route_probe_command(LiveLabPlatform::Windows, "1.1.1.1")
                .contains("Find-NetRoute")
        );
    }

    #[test]
    fn compute_ttl_decrement_requires_both_probes_attempted_and_parsed() {
        let attempted_63 = super::TtlProbe {
            attempted: true,
            ttl: Some(63),
        };
        let attempted_61 = super::TtlProbe {
            attempted: true,
            ttl: Some(61),
        };
        assert_eq!(
            super::compute_ttl_decrement(&attempted_63, &attempted_61),
            Some(2)
        );
        // A not-attempted probe yields None (fail-closed), never a silent 0.
        assert_eq!(
            super::compute_ttl_decrement(&super::TtlProbe::not_attempted(), &attempted_61),
            None
        );
        // Attempted but unparsed TTL also fails closed.
        let attempted_no_ttl = super::TtlProbe {
            attempted: true,
            ttl: None,
        };
        assert_eq!(
            super::compute_ttl_decrement(&attempted_63, &attempted_no_ttl),
            None
        );
    }

    #[test]
    fn evaluate_two_hop_dataplane_proof_passes_on_reach_and_ttl_minus_one() {
        // Baseline 64: the entry originates the reply over a direct peer link,
        // zero forwards. Two-hop 63: the final exit originates the reply and the
        // entry forwards it back exactly once. See
        // EXPECTED_PER_HOP_TTL_DECREMENT for the derivation.
        let proof = super::evaluate_two_hop_dataplane_proof(
            &super::EndToEndProbe {
                attempted: true,
                reachable: true,
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(64),
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(63),
            },
        );
        assert!(proof.end_to_end_reachable);
        assert_eq!(proof.per_hop_ttl_decrement, Some(1));
        assert!(proof.per_hop_ttl_decrement_ok);
    }

    #[test]
    fn evaluate_two_hop_dataplane_proof_fails_closed_on_unattempted_end_to_end() {
        // A never-run end-to-end probe must NOT count as reachable, mirroring
        // the ipv6_leak `probe_attempted` discipline.
        let proof = super::evaluate_two_hop_dataplane_proof(
            &super::EndToEndProbe {
                attempted: false,
                reachable: false,
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(64),
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(63),
            },
        );
        assert!(!proof.end_to_end_reachable);
        // The per-hop sub-proof can still be valid independently.
        assert!(proof.per_hop_ttl_decrement_ok);
    }

    #[test]
    fn evaluate_two_hop_dataplane_proof_rejects_wrong_ttl_delta() {
        // A no-forward delta (0) must not satisfy the two-hop per-hop
        // assertion, and neither may a delta LARGER than expected (2, 3) —
        // those mean an extra unexplained forwarding hop on the reply path.
        // Only an exact −1 proves the entry relayed the reply onward exactly
        // once. The comparison is deliberately exact, never a threshold.
        for (baseline, two_hop) in [(64u8, 64u8), (64, 62), (64, 61)] {
            let proof = super::evaluate_two_hop_dataplane_proof(
                &super::EndToEndProbe {
                    attempted: true,
                    reachable: true,
                },
                &super::TtlProbe {
                    attempted: true,
                    ttl: Some(baseline),
                },
                &super::TtlProbe {
                    attempted: true,
                    ttl: Some(two_hop),
                },
            );
            assert!(
                !proof.per_hop_ttl_decrement_ok,
                "delta {} must fail the exact -1 per-hop assertion",
                i32::from(baseline) - i32::from(two_hop)
            );
        }
    }

    #[test]
    fn evaluate_two_hop_dataplane_proof_requires_the_absolute_baseline_not_just_the_delta() {
        // (63, 62) has the correct delta of 1 but an impossible baseline: a reply
        // from the entry across a direct peer link cannot have been forwarded. The
        // delta alone would accept this identically to (64, 63), so the absolute
        // baseline must be asserted too or the derivation does not bind.
        let proof = super::evaluate_two_hop_dataplane_proof(
            &super::EndToEndProbe {
                attempted: true,
                reachable: true,
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(63),
            },
            &super::TtlProbe {
                attempted: true,
                ttl: Some(62),
            },
        );
        assert_eq!(proof.per_hop_ttl_decrement, Some(1));
        assert!(
            !proof.per_hop_ttl_decrement_ok,
            "a baseline of 63 must fail even with the expected delta"
        );
    }

    #[test]
    fn evaluate_two_hop_dataplane_proof_fails_closed_on_unattempted_ttl_probe() {
        let proof = super::evaluate_two_hop_dataplane_proof(
            &super::EndToEndProbe {
                attempted: true,
                reachable: true,
            },
            &super::TtlProbe::not_attempted(),
            &super::TtlProbe {
                attempted: true,
                ttl: Some(61),
            },
        );
        assert_eq!(proof.per_hop_ttl_decrement, None);
        assert!(!proof.per_hop_ttl_decrement_ok);
    }
}
