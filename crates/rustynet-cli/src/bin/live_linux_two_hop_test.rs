#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, append_env_assignment, capture_root, create_workspace, enforce_host,
    ensure_pinned_known_hosts_file, ensure_safe_spec, ensure_safe_token, git_head_commit,
    issue_assignment_bundles_from_env, issue_traversal_bundles_from_env,
    load_home_known_hosts_path, no_plaintext_passphrase_check, remote_src_dir, require_command,
    resolved_target_address, run_root, scp_to, seed_known_hosts, shell_quote, status, unix_now,
    wait_for_daemon_socket, write_assignment_refresh_env, write_file,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;
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

    let nodes_spec = format!(
        "{}|{}:51820|{};{}|{}:51820|{};{}|{}:51820|{};{}|{}:51820|{}",
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
    let allow_spec = format!(
        "{}|{};{}|{};{}|{};{}|{};{}|{};{}|{};{}|{};{}|{}",
        config.client_node_id,
        config.entry_node_id,
        config.entry_node_id,
        config.client_node_id,
        config.client_node_id,
        config.final_exit_node_id,
        config.final_exit_node_id,
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

    logger.line("[two-hop] advertising default route on final exit and entry relay")?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.final_exit_host,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0",
    )?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.entry_host,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0",
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
            "ip -4 route get 1.1.1.1 || true",
        )?;
        second_client_route = capture_root(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.second_client_host,
            "ip -4 route get 1.1.1.1 || true",
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
        status_field(&entry_status, "managed_peer_endpoints").unwrap_or_else(|| "none".to_string());
    let entry_managed_peer_endpoints_error =
        status_field(&entry_status, "managed_peer_endpoints_error")
            .unwrap_or_else(|| "none".to_string());
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
    let check_client_route_rustynet = if client_route.contains("dev rustynet0") {
        "pass"
    } else {
        "fail"
    };
    let check_second_client_route_rustynet = if second_client_route.contains("dev rustynet0") {
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

    let overall = [
        check_client_exit_is_entry,
        check_entry_exit_is_final,
        check_entry_serves_exit,
        check_final_exit_serves,
        check_client_route_rustynet,
        check_second_client_route_rustynet,
        check_entry_managed_peer_endpoints_visible,
        check_no_plaintext_passphrases,
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
        "{{\n  \"phase\": \"phase10\",\n  \"mode\": \"live_linux_two_hop\",\n  \"evidence_mode\": \"measured\",\n  \"captured_at\": \"{}\",\n  \"captured_at_unix\": {},\n  \"git_commit\": \"{}\",\n  \"status\": \"{}\",\n  \"final_exit_host\": \"{}\",\n  \"client_host\": \"{}\",\n  \"entry_host\": \"{}\",\n  \"second_client_host\": \"{}\",\n  \"proof_sources\": {{\n    \"entry_peer_visibility\": \"managed_peer_endpoints\",\n    \"entry_peer_visibility_error_field\": \"managed_peer_endpoints_error\",\n    \"entry_peer_visibility_debug_only\": \"wg_show_endpoints\"\n  }},\n  \"checks\": {{\n    \"client_exit_is_entry\": \"{}\",\n    \"entry_exit_is_final\": \"{}\",\n    \"entry_serves_exit\": \"{}\",\n    \"final_exit_serves\": \"{}\",\n    \"client_route_via_rustynet0\": \"{}\",\n    \"second_client_route_via_rustynet0\": \"{}\",\n    \"entry_peer_visibility\": \"{}\",\n    \"entry_managed_peer_endpoints_visible\": \"{}\",\n    \"no_plaintext_passphrase_files\": \"{}\"\n  }},\n  \"source_artifacts\": [\n    \"{}\"\n  ]\n}}\n",
        captured_at_utc,
        captured_at_unix,
        git_commit,
        if overall { "pass" } else { "fail" },
        config.final_exit_host,
        config.client_host,
        config.entry_host,
        config.second_client_host,
        check_client_exit_is_entry,
        check_entry_exit_is_final,
        check_entry_serves_exit,
        check_final_exit_serves,
        check_client_route_rustynet,
        check_second_client_route_rustynet,
        check_entry_managed_peer_endpoints_visible,
        check_entry_managed_peer_endpoints_visible,
        check_no_plaintext_passphrases,
        config.log_path.display(),
    );
    write_file(&config.report_path, &report)?;
    logger.line(format!("[two-hop] report written: {}", config.report_path.display()).as_str())?;
    if !overall {
        return Err("two-hop validation failed".to_string());
    }

    Ok(())
}

#[derive(Debug)]
struct Config {
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
            ssh_identity_file: PathBuf::new(),
            final_exit_host: "debian@192.168.18.49".to_string(),
            client_host: "debian@192.168.18.65".to_string(),
            entry_host: "ubuntu@192.168.18.52".to_string(),
            second_client_host: "fedora@192.168.18.51".to_string(),
            final_exit_node_id: "exit-49".to_string(),
            client_node_id: "client-65".to_string(),
            entry_node_id: "client-52".to_string(),
            second_client_node_id: "client-51".to_string(),
            ssh_allow_cidrs: "192.168.18.0/24".to_string(),
            report_path: PathBuf::from("artifacts/phase10/live_linux_two_hop_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_two_hop.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?)
                }
                "--final-exit-host" => config.final_exit_host = next_value(&mut iter, &arg)?,
                "--client-host" => config.client_host = next_value(&mut iter, &arg)?,
                "--entry-host" => config.entry_host = next_value(&mut iter, &arg)?,
                "--second-client-host" => config.second_client_host = next_value(&mut iter, &arg)?,
                "--final-exit-node-id" => config.final_exit_node_id = next_value(&mut iter, &arg)?,
                "--client-node-id" => config.client_node_id = next_value(&mut iter, &arg)?,
                "--entry-node-id" => config.entry_node_id = next_value(&mut iter, &arg)?,
                "--second-client-node-id" => {
                    config.second_client_node_id = next_value(&mut iter, &arg)?
                }
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?))
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
                "usage: live_linux_two_hop_test --ssh-identity-file <path> [options]".to_string(),
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
        "install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle",
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

fn refresh_signed_state(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh",
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
        && entry_status.contains(&format!("exit_node={}", config.final_exit_node_id))
        && entry_status.contains("serving_exit_node=true")
        && final_exit_status.contains("serving_exit_node=true")
        && second_client_status.contains(&format!("exit_node={}", config.final_exit_node_id))
        && second_client_status.contains("state=ExitActive")
        && client_route.contains("dev rustynet0")
        && second_client_route.contains("dev rustynet0")
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
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_field_extracts_managed_peer_endpoints() {
        let status = "node_id=client-2 managed_peer_endpoints=client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820 managed_peer_endpoints_error=none";
        assert_eq!(
            super::status_field(status, "managed_peer_endpoints"),
            Some("client-1/192.168.64.24:51820+exit-1/192.168.64.22:51820".to_string())
        );
        assert_eq!(
            super::status_field(status, "managed_peer_endpoints_error"),
            Some("none".to_string())
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
    fn two_hop_runtime_ready_requires_expected_exit_chain_and_routes() {
        let config = super::Config {
            ssh_identity_file: std::path::PathBuf::from("/tmp/key"),
            final_exit_host: "debian@192.168.64.22".to_string(),
            client_host: "debian@192.168.64.24".to_string(),
            entry_host: "debian@192.168.64.26".to_string(),
            second_client_host: "debian@192.168.64.29".to_string(),
            final_exit_node_id: "exit-1".to_string(),
            client_node_id: "client-1".to_string(),
            entry_node_id: "client-2".to_string(),
            second_client_node_id: "client-4".to_string(),
            ssh_allow_cidrs: "192.168.64.0/24".to_string(),
            report_path: std::path::PathBuf::from("/tmp/report.json"),
            log_path: std::path::PathBuf::from("/tmp/report.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
        };

        assert!(super::two_hop_runtime_ready(
            &config,
            "node_role=client state=ExitActive exit_node=client-2",
            "node_role=admin state=ExitActive exit_node=exit-1 serving_exit_node=true",
            "node_role=admin state=ExitActive serving_exit_node=true",
            "node_role=client state=ExitActive exit_node=exit-1",
            "1.1.1.1 dev rustynet0",
            "1.1.1.1 dev rustynet0",
        ));
        assert!(!super::two_hop_runtime_ready(
            &config,
            "node_role=client state=ExitActive exit_node=client-2",
            "node_role=admin state=ExitActive exit_node=exit-1 serving_exit_node=true",
            "node_role=admin state=ExitActive serving_exit_node=true",
            "node_role=client state=ExitActive exit_node=exit-1",
            "1.1.1.1 dev rustynet0",
            "1.1.1.1 via 192.168.64.1 dev enp0s1",
        ));
    }
}
