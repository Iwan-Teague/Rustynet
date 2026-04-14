#![forbid(unsafe_code)]

mod live_lab_bin_support;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, apply_role_coupling, capture_root, create_workspace, enforce_host, field_value,
    git_head_commit, read_last_matching_line, remote_src_dir, require_command, run_cargo_ops,
    run_root, scp_to, shell_quote, ssh_status, status, unix_now, wait_for_daemon_socket,
    write_file,
};

const ROLE_SWITCH_ROUTE_CONVERGENCE_TIMEOUT_SECS: u64 = 20;

#[derive(Clone, Debug)]
struct SignedStateRefreshTarget {
    host: String,
    node_id: String,
}

#[derive(Clone, Debug)]
struct SignedStateRefreshContext {
    traversal_env_file: PathBuf,
    dns_zone_env_file: PathBuf,
    exit_host: String,
    targets: Vec<SignedStateRefreshTarget>,
}

struct RoleSwitchRunContext<'a> {
    logger: &'a mut Logger,
    identity: &'a Path,
    known_hosts: &'a Path,
    ssh_allow_cidrs: &'a str,
    hosts_json_path: &'a Path,
    workspace_dir: &'a Path,
    signed_state_refresh: Option<&'a SignedStateRefreshContext>,
}

#[derive(Clone, Copy)]
struct HostSwitchSpec<'a> {
    host: &'a str,
    os_id: &'a str,
    temp_role: &'a str,
    node_id: &'a str,
}

struct ClientRoleContext<'a> {
    logger: &'a mut Logger,
    identity: &'a Path,
    known_hosts: &'a Path,
    host: &'a str,
    node_id: &'a str,
    ssh_allow_cidrs: &'a str,
    workspace_dir: &'a Path,
    signed_state_refresh: Option<&'a SignedStateRefreshContext>,
}

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

    if !config.ssh_identity_file.is_file() {
        return Err(format!(
            "missing ssh identity file: {}",
            config.ssh_identity_file.display()
        ));
    }
    if config.ssh_identity_file.is_symlink() {
        return Err(format!(
            "ssh identity file must not be a symlink: {}",
            config.ssh_identity_file.display()
        ));
    }
    live_lab_support::run_cargo_ops(
        &root_dir,
        "check-local-file-mode",
        &[
            OsString::from("--path"),
            config.ssh_identity_file.clone().into_os_string(),
            OsString::from("--policy"),
            OsString::from("owner-only"),
            OsString::from("--label"),
            OsString::from("ssh identity file"),
        ],
    )?;

    let pinned_known_hosts = match &config.pinned_known_hosts_file {
        Some(path) => path.clone(),
        None => live_lab_support::load_home_known_hosts_path()?,
    };
    live_lab_support::ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("role-switch-live")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    live_lab_support::seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;
    let mut logger = Logger::new(&config.log_path)?;
    let mut source_body = String::new();
    let git_commit = config.git_commit.clone().unwrap_or_else(|| {
        git_head_commit(&root_dir).unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        })
    });
    let captured_at_unix = unix_now();
    let captured_at_utc = utc_now_string();
    source_body.push_str("# Role Switch Matrix (current commit)\n\n");
    source_body.push_str(format!("Captured at: {captured_at_utc}\n\n").as_str());

    let tmp_json = workspace.path().join("role_switch_hosts.json");
    write_file(&tmp_json, "{}\n")?;

    logger.line("[role-switch] starting live role-switch matrix validation")?;

    let signed_state_refresh = build_signed_state_refresh_context(&config)?;
    let mut run_context = RoleSwitchRunContext {
        logger: &mut logger,
        identity: &config.ssh_identity_file,
        known_hosts: &work_known_hosts,
        ssh_allow_cidrs: &config.ssh_allow_cidrs,
        hosts_json_path: &tmp_json,
        workspace_dir: workspace.path(),
        signed_state_refresh: signed_state_refresh.as_ref(),
    };

    let mut overall_status = "pass".to_string();
    for host in [
        HostSwitchSpec {
            host: &config.debian_host,
            os_id: "debian13",
            temp_role: "admin",
            node_id: &config.debian_node_id,
        },
        HostSwitchSpec {
            host: &config.fedora_host,
            os_id: "fedora",
            temp_role: "blind_exit",
            node_id: &config.fedora_node_id,
        },
        HostSwitchSpec {
            host: &config.ubuntu_host,
            os_id: "ubuntu",
            temp_role: "admin",
            node_id: &config.ubuntu_node_id,
        },
        HostSwitchSpec {
            host: &config.mint_host,
            os_id: "mint",
            temp_role: "admin",
            node_id: &config.mint_node_id,
        },
    ] {
        process_host(
            &mut run_context,
            host,
            &mut source_body,
            &mut overall_status,
        )?;
    }

    write_file(&config.source_path, &source_body)?;

    run_cargo_ops(
        &root_dir,
        "write-role-switch-matrix-report",
        &[
            OsString::from("--hosts-json-path"),
            tmp_json.as_os_str().to_os_string(),
            OsString::from("--report-path"),
            config.report_path.clone().into_os_string(),
            OsString::from("--source-path"),
            config.source_path.clone().into_os_string(),
            OsString::from("--git-commit"),
            OsString::from(git_commit),
            OsString::from("--captured-at-unix"),
            OsString::from(captured_at_unix.to_string()),
            OsString::from("--overall-status"),
            OsString::from(overall_status.clone()),
        ],
    )?;

    logger.line(format!("role_switch_report={}", config.report_path.display()).as_str())?;
    logger.line(format!("role_switch_source={}", config.source_path.display()).as_str())?;

    if overall_status != "pass" {
        return Err("role-switch matrix validation failed".to_string());
    }

    Ok(())
}

#[derive(Debug)]
struct Config {
    ssh_identity_file: PathBuf,
    exit_host: String,
    exit_node_id: String,
    debian_host: String,
    debian_node_id: String,
    ubuntu_host: String,
    ubuntu_node_id: String,
    fedora_host: String,
    fedora_node_id: String,
    mint_host: String,
    mint_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    source_path: PathBuf,
    log_path: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
    git_commit: Option<String>,
    traversal_env_file: Option<PathBuf>,
    dns_zone_env_file: Option<PathBuf>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            ssh_identity_file: PathBuf::new(),
            exit_host: "debian@192.168.18.50".to_string(),
            exit_node_id: "exit-50".to_string(),
            debian_host: "debian@192.168.18.65".to_string(),
            debian_node_id: "client-65".to_string(),
            ubuntu_host: "ubuntu@192.168.18.52".to_string(),
            ubuntu_node_id: "client-52".to_string(),
            fedora_host: "fedora@192.168.18.51".to_string(),
            fedora_node_id: "client-51".to_string(),
            mint_host: "mint@192.168.18.53".to_string(),
            mint_node_id: "client-53".to_string(),
            ssh_allow_cidrs: "192.168.18.0/24".to_string(),
            report_path: PathBuf::from("artifacts/phase10/role_switch_matrix_report.json"),
            source_path: PathBuf::from("artifacts/phase10/source/role_switch_matrix.md"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_role_switch_matrix.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
            traversal_env_file: None,
            dns_zone_env_file: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?)
                }
                "--exit-host" => config.exit_host = next_value(&mut iter, &arg)?,
                "--exit-node-id" => config.exit_node_id = next_value(&mut iter, &arg)?,
                "--debian-host" => config.debian_host = next_value(&mut iter, &arg)?,
                "--debian-node-id" => config.debian_node_id = next_value(&mut iter, &arg)?,
                "--ubuntu-host" => config.ubuntu_host = next_value(&mut iter, &arg)?,
                "--ubuntu-node-id" => config.ubuntu_node_id = next_value(&mut iter, &arg)?,
                "--fedora-host" => config.fedora_host = next_value(&mut iter, &arg)?,
                "--fedora-node-id" => config.fedora_node_id = next_value(&mut iter, &arg)?,
                "--mint-host" => config.mint_host = next_value(&mut iter, &arg)?,
                "--mint-node-id" => config.mint_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--source-path" => config.source_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "--git-commit" => config.git_commit = Some(next_value(&mut iter, &arg)?),
                "--traversal-env-file" => {
                    config.traversal_env_file = Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "--dns-zone-env-file" => {
                    config.dns_zone_env_file = Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_role_switch_matrix_test --ssh-identity-file <path> [options]"
                    .to_string(),
            );
        }
        for (label, value) in [
            ("debian-host", config.debian_host.as_str()),
            ("debian-node-id", config.debian_node_id.as_str()),
            ("exit-host", config.exit_host.as_str()),
            ("exit-node-id", config.exit_node_id.as_str()),
            ("ubuntu-host", config.ubuntu_host.as_str()),
            ("ubuntu-node-id", config.ubuntu_node_id.as_str()),
            ("fedora-host", config.fedora_host.as_str()),
            ("fedora-node-id", config.fedora_node_id.as_str()),
            ("mint-host", config.mint_host.as_str()),
            ("mint-node-id", config.mint_node_id.as_str()),
            ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ] {
            live_lab_support::ensure_safe_token(label, value)?;
        }
        if let Some(path) = &config.traversal_env_file
            && !path.is_file()
        {
            return Err(format!("missing traversal env file: {}", path.display()));
        }
        if let Some(path) = &config.dns_zone_env_file
            && !path.is_file()
        {
            return Err(format!("missing dns zone env file: {}", path.display()));
        }
        Ok(config)
    }
}

fn build_signed_state_refresh_context(
    config: &Config,
) -> Result<Option<SignedStateRefreshContext>, String> {
    match (
        config.traversal_env_file.as_ref(),
        config.dns_zone_env_file.as_ref(),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(
            "role-switch signed-state refresh requires --dns-zone-env-file when --traversal-env-file is set"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "role-switch signed-state refresh requires --traversal-env-file when --dns-zone-env-file is set"
                .to_string(),
        ),
        (Some(traversal_env_file), Some(dns_zone_env_file)) => {
            Ok(Some(SignedStateRefreshContext {
                traversal_env_file: traversal_env_file.clone(),
                dns_zone_env_file: dns_zone_env_file.clone(),
                exit_host: config.exit_host.clone(),
                targets: vec![
                    SignedStateRefreshTarget {
                        host: config.exit_host.clone(),
                        node_id: config.exit_node_id.clone(),
                    },
                    SignedStateRefreshTarget {
                        host: config.debian_host.clone(),
                        node_id: config.debian_node_id.clone(),
                    },
                    SignedStateRefreshTarget {
                        host: config.ubuntu_host.clone(),
                        node_id: config.ubuntu_node_id.clone(),
                    },
                    SignedStateRefreshTarget {
                        host: config.fedora_host.clone(),
                        node_id: config.fedora_node_id.clone(),
                    },
                    SignedStateRefreshTarget {
                        host: config.mint_host.clone(),
                        node_id: config.mint_node_id.clone(),
                    },
                ],
            }))
        }
    }
}

fn process_host(
    context: &mut RoleSwitchRunContext<'_>,
    spec: HostSwitchSpec<'_>,
    source_body: &mut String,
    overall_status: &mut String,
) -> Result<(), String> {
    context.logger.line(
        format!(
            "[role-switch] {} {} -> {}",
            spec.os_id, spec.host, spec.temp_role
        )
        .as_str(),
    )?;
    let (baseline, baseline_exit) = {
        let mut client_role = ClientRoleContext {
            logger: &mut *context.logger,
            identity: context.identity,
            known_hosts: context.known_hosts,
            host: spec.host,
            node_id: spec.node_id,
            ssh_allow_cidrs: context.ssh_allow_cidrs,
            workspace_dir: context.workspace_dir,
            signed_state_refresh: context.signed_state_refresh,
        };
        let baseline = ensure_client_role(&mut client_role)?;
        let baseline_exit = field_value(&baseline, "exit_node");
        (baseline, baseline_exit)
    };

    switch_role(
        context.identity,
        context.known_hosts,
        spec.host,
        spec.temp_role,
        spec.node_id,
        context.ssh_allow_cidrs,
    )?;
    if let Some(refresh) = context.signed_state_refresh {
        refresh_signed_state_for_transition(
            context.logger,
            context.identity,
            context.known_hosts,
            context.workspace_dir,
            refresh,
            spec.host,
            format!(
                "before waiting for {} to settle as {}",
                spec.node_id, spec.temp_role
            )
            .as_str(),
        )?;
    }
    let after_temp = wait_for_role(
        context.identity,
        context.known_hosts,
        spec.host,
        spec.temp_role,
    )?;

    let mut switch_execution = "fail";
    let mut post_switch_reconcile = "fail";
    let mut policy_still_enforced = "fail";
    let mut least_privilege_preserved = "fail";

    if spec.temp_role == "blind_exit" {
        if route_advertise_denied(context.identity, context.known_hosts, spec.host)? {
            policy_still_enforced = "pass";
        }
        if exit_select_denied(
            context.identity,
            context.known_hosts,
            spec.host,
            &baseline_exit,
        )? && lan_toggle_denied(context.identity, context.known_hosts, spec.host)?
        {
            least_privilege_preserved = "pass";
        }
    } else if route_advertise_denied(context.identity, context.known_hosts, spec.host)? {
        policy_still_enforced = "pass";
        least_privilege_preserved = "pass";
    }

    let mut restore_context = ClientRoleContext {
        logger: &mut *context.logger,
        identity: context.identity,
        known_hosts: context.known_hosts,
        host: spec.host,
        node_id: spec.node_id,
        ssh_allow_cidrs: context.ssh_allow_cidrs,
        workspace_dir: context.workspace_dir,
        signed_state_refresh: context.signed_state_refresh,
    };
    let after_restore =
        ensure_client_role_with_expected_exit(&mut restore_context, Some(&baseline_exit))?;

    if field_value(&after_temp, "node_role") == spec.temp_role
        && field_value(&after_restore, "node_role") == "client"
    {
        switch_execution = "pass";
    }

    if spec.temp_role == "blind_exit" {
        if field_value(&after_temp, "serving_exit_node") == "true"
            && field_value(&after_temp, "exit_node") == "none"
            && field_value(&after_temp, "lan_access") == "off"
            && !baseline_exit.is_empty()
            && baseline_exit != "none"
            && client_exit_route_converged(&after_restore, &baseline_exit)
        {
            post_switch_reconcile = "pass";
        }
    } else if !baseline_exit.is_empty()
        && baseline_exit != "none"
        && field_value(&after_temp, "serving_exit_node") == "false"
        && field_value(&after_temp, "exit_node") == baseline_exit
        && client_exit_route_converged(&after_restore, &baseline_exit)
    {
        post_switch_reconcile = "pass";
    }

    source_body.push_str(format!("## {} ({})\n", spec.os_id, spec.host).as_str());
    source_body.push_str(format!("- baseline: {}\n", sanitize_line(&baseline)).as_str());
    source_body.push_str(format!("- after_temp: {}\n", sanitize_line(&after_temp)).as_str());
    source_body
        .push_str(format!("- after_restore: {}\n\n", sanitize_line(&after_restore)).as_str());

    run_cargo_ops(
        &live_lab_support::repo_root()?,
        "update-role-switch-host-result",
        &[
            OsString::from("--hosts-json-path"),
            context.hosts_json_path.as_os_str().to_os_string(),
            OsString::from("--os-id"),
            OsString::from(spec.os_id),
            OsString::from("--temp-role"),
            OsString::from(spec.temp_role),
            OsString::from("--switch-execution"),
            OsString::from(switch_execution),
            OsString::from("--post-switch-reconcile"),
            OsString::from(post_switch_reconcile),
            OsString::from("--policy-still-enforced"),
            OsString::from(policy_still_enforced),
            OsString::from("--least-privilege-preserved"),
            OsString::from(least_privilege_preserved),
        ],
    )?;

    if switch_execution != "pass"
        || post_switch_reconcile != "pass"
        || policy_still_enforced != "pass"
        || least_privilege_preserved != "pass"
    {
        *overall_status = "fail".to_string();
    }
    Ok(())
}

fn switch_role(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    role: &str,
    node_id: &str,
    ssh_allow_cidrs: &str,
) -> Result<(), String> {
    enforce_host(
        identity,
        known_hosts,
        host,
        role,
        node_id,
        &remote_src_dir(host),
        ssh_allow_cidrs,
    )?;
    wait_for_daemon_socket(
        identity,
        known_hosts,
        host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )
}

fn ensure_client_role(context: &mut ClientRoleContext<'_>) -> Result<String, String> {
    ensure_client_role_with_expected_exit(context, None)
}

fn ensure_client_role_with_expected_exit(
    context: &mut ClientRoleContext<'_>,
    expected_exit: Option<&str>,
) -> Result<String, String> {
    let baseline =
        capture_client_role_snapshot(context.identity, context.known_hosts, context.host)?;
    let baseline_exit = expected_exit
        .filter(|value| !value.is_empty() && *value != "none")
        .map(|value| value.to_string())
        .unwrap_or_else(|| field_value(&baseline, "exit_node"));
    if baseline_exit.is_empty() || baseline_exit == "none" {
        if role_runtime_ready(&baseline, "client") {
            return Ok(baseline);
        }
    } else if client_exit_route_converged(&baseline, &baseline_exit) {
        return Ok(baseline);
    }

    switch_role(
        context.identity,
        context.known_hosts,
        context.host,
        "client",
        context.node_id,
        context.ssh_allow_cidrs,
    )?;
    if baseline_exit.is_empty() || baseline_exit == "none" {
        apply_role_coupling(
            context.identity,
            context.known_hosts,
            context.host,
            "client",
            None,
            false,
            "/etc/rustynet/assignment-refresh.env",
        )?;
    } else {
        apply_role_coupling(
            context.identity,
            context.known_hosts,
            context.host,
            "client",
            Some(baseline_exit.as_str()),
            false,
            "/etc/rustynet/assignment-refresh.env",
        )?;
    }
    force_runtime_state_refresh(context.identity, context.known_hosts, context.host)?;
    if let Some(refresh) = context.signed_state_refresh {
        refresh_signed_state_for_transition(
            context.logger,
            context.identity,
            context.known_hosts,
            context.workspace_dir,
            refresh,
            context.host,
            format!("before restoring {} to client", context.node_id).as_str(),
        )?;
    }
    let after_switch = wait_for_role(
        context.identity,
        context.known_hosts,
        context.host,
        "client",
    )?;
    let restore_exit = expected_exit
        .filter(|value| !value.is_empty() && *value != "none")
        .map(|value| value.to_string())
        .unwrap_or_else(|| field_value(&after_switch, "exit_node"));
    if restore_exit.is_empty() || restore_exit == "none" {
        Ok(after_switch)
    } else {
        wait_for_client_exit_route_convergence(
            context.identity,
            context.known_hosts,
            context.host,
            &restore_exit,
        )
    }
}

fn refresh_signed_state_for_transition(
    logger: &mut Logger,
    identity: &Path,
    known_hosts: &Path,
    workspace_dir: &Path,
    refresh: &SignedStateRefreshContext,
    target_host: &str,
    reason: &str,
) -> Result<(), String> {
    refresh_traversal_bundles_for_transition(
        logger,
        identity,
        known_hosts,
        workspace_dir,
        refresh,
        reason,
    )?;
    refresh_dns_zone_bundles_for_transition(identity, known_hosts, workspace_dir, refresh)?;
    for target in &refresh.targets {
        refresh_trust_evidence(identity, known_hosts, target.host.as_str())?;
        refresh_signed_state(identity, known_hosts, target.host.as_str())?;
    }
    force_runtime_state_refresh_targets_ordered(
        identity,
        known_hosts,
        refresh.targets.as_slice(),
        refresh.exit_host.as_str(),
        target_host,
    )?;
    Ok(())
}

fn refresh_traversal_bundles_for_transition(
    logger: &mut Logger,
    identity: &Path,
    known_hosts: &Path,
    workspace_dir: &Path,
    refresh: &SignedStateRefreshContext,
    reason: &str,
) -> Result<(), String> {
    let issue_dir = workspace_dir.join(format!(
        "role-switch-traversal-{}-{}",
        sanitize_path_component(reason),
        unix_now()
    ));
    let remote_env_path = "/tmp/rn-role-switch-traversal.env";
    let remote_issue_dir = "/run/rustynet/role-switch-traversal-issue";
    logger.line(format!("[role-switch] refresh traversal {reason}").as_str())?;
    fs::create_dir_all(&issue_dir).map_err(|err| {
        format!(
            "failed to create role-switch traversal workspace {}: {err}",
            issue_dir.display()
        )
    })?;
    scp_to(
        identity,
        known_hosts,
        refresh.traversal_env_file.as_path(),
        refresh.exit_host.as_str(),
        remote_env_path,
    )?;
    if let Err(err) = run_root(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        format!(
            "rustynet ops e2e-issue-traversal-bundles-from-env --env-file '{}' --issue-dir '{}'",
            remote_env_path, remote_issue_dir
        )
        .as_str(),
    ) {
        let _ = run_root(
            identity,
            known_hosts,
            refresh.exit_host.as_str(),
            format!("rm -f '{}'", remote_env_path).as_str(),
        );
        return Err(err);
    }
    let _ = run_root(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        format!("rm -f '{}'", remote_env_path).as_str(),
    );

    let verifier_key = issue_dir.join("rn-traversal.pub");
    capture_root_file_to_path(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        &format!("{remote_issue_dir}/rn-traversal.pub"),
        verifier_key.as_path(),
    )?;

    for target in &refresh.targets {
        let bundle = issue_dir.join(format!("rn-traversal-{}.traversal", target.node_id));
        capture_root_file_to_path(
            identity,
            known_hosts,
            refresh.exit_host.as_str(),
            &format!(
                "{remote_issue_dir}/rn-traversal-{}.traversal",
                target.node_id
            ),
            bundle.as_path(),
        )?;
        scp_to(
            identity,
            known_hosts,
            verifier_key.as_path(),
            target.host.as_str(),
            "/tmp/rn-traversal.pub",
        )?;
        scp_to(
            identity,
            known_hosts,
            bundle.as_path(),
            target.host.as_str(),
            "/tmp/rn-traversal.bundle",
        )?;
        run_root(
            identity,
            known_hosts,
            target.host.as_str(),
            "if ! getent group rustynetd >/dev/null 2>&1; then groupadd --system rustynetd; fi && install -d -m 0750 -o root -g rustynetd /etc/rustynet && install -d -m 0700 -o rustynetd -g rustynetd /var/lib/rustynet && install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle",
        )?;
    }

    Ok(())
}

fn refresh_dns_zone_bundles_for_transition(
    identity: &Path,
    known_hosts: &Path,
    workspace_dir: &Path,
    refresh: &SignedStateRefreshContext,
) -> Result<(), String> {
    let issue_dir = workspace_dir.join(format!("role-switch-dns-{}", unix_now()));
    let remote_env_path = "/tmp/rn-role-switch-dns.env";
    let remote_issue_dir = "/run/rustynet/dns-zone-issue";
    fs::create_dir_all(&issue_dir).map_err(|err| {
        format!(
            "failed to create role-switch dns workspace {}: {err}",
            issue_dir.display()
        )
    })?;
    scp_to(
        identity,
        known_hosts,
        refresh.dns_zone_env_file.as_path(),
        refresh.exit_host.as_str(),
        remote_env_path,
    )?;
    if let Err(err) = run_root(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        format!(
            "rustynet ops e2e-issue-dns-zone-bundles-from-env --env-file '{}' --issue-dir '{}'",
            remote_env_path, remote_issue_dir
        )
        .as_str(),
    ) {
        let _ = run_root(
            identity,
            known_hosts,
            refresh.exit_host.as_str(),
            format!("rm -f '{}'", remote_env_path).as_str(),
        );
        return Err(err);
    }
    let _ = run_root(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        format!("rm -f '{}'", remote_env_path).as_str(),
    );

    let verifier_key = issue_dir.join("rn-dns-zone.pub");
    capture_root_file_to_path(
        identity,
        known_hosts,
        refresh.exit_host.as_str(),
        &format!("{remote_issue_dir}/rn-dns-zone.pub"),
        verifier_key.as_path(),
    )?;

    for target in &refresh.targets {
        let bundle = issue_dir.join(format!("rn-dns-zone-{}.dns-zone", target.node_id));
        capture_root_file_to_path(
            identity,
            known_hosts,
            refresh.exit_host.as_str(),
            &format!("{remote_issue_dir}/rn-dns-zone-{}.dns-zone", target.node_id),
            bundle.as_path(),
        )?;
        install_dns_zone_bundle(
            identity,
            known_hosts,
            target.host.as_str(),
            verifier_key.as_path(),
            bundle.as_path(),
        )?;
    }
    Ok(())
}

fn capture_root_file_to_path(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let command = format!("cat {}", shell_quote(remote_path));
    let contents = capture_root(identity, known_hosts, host, command.as_str())?;
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create local traversal capture dir {}: {err}",
                parent.display()
            )
        })?;
    }
    fs::write(local_path, contents).map_err(|err| {
        format!(
            "failed to write captured traversal file {}: {err}",
            local_path.display()
        )
    })
}

fn force_runtime_state_refresh_targets_ordered(
    identity: &Path,
    known_hosts: &Path,
    targets: &[SignedStateRefreshTarget],
    exit_host: &str,
    target_host: &str,
) -> Result<(), String> {
    for target in targets
        .iter()
        .filter(|target| target.host.as_str() != exit_host && target.host.as_str() != target_host)
    {
        force_runtime_state_refresh(identity, known_hosts, target.host.as_str())?;
    }
    if exit_host != target_host {
        let exit_target = targets
            .iter()
            .find(|target| target.host.as_str() == exit_host)
            .ok_or_else(|| format!("missing exit traversal refresh target: {exit_host}"))?;
        force_runtime_state_refresh(identity, known_hosts, exit_target.host.as_str())?;
    }
    let restore_target = targets
        .iter()
        .find(|target| target.host.as_str() == target_host)
        .ok_or_else(|| format!("missing restore traversal refresh target: {target_host}"))?;
    force_runtime_state_refresh(identity, known_hosts, restore_target.host.as_str())?;
    Ok(())
}

fn refresh_trust_evidence(identity: &Path, known_hosts: &Path, host: &str) -> Result<(), String> {
    wait_for_daemon_socket(
        identity,
        known_hosts,
        host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    run_root(
        identity,
        known_hosts,
        host,
        "rustynet ops refresh-signed-trust",
    )
}

fn refresh_signed_state(identity: &Path, known_hosts: &Path, host: &str) -> Result<(), String> {
    wait_for_daemon_socket(
        identity,
        known_hosts,
        host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    run_root(
        identity,
        known_hosts,
        host,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh",
    )
}

fn force_runtime_state_refresh(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        host,
        "rustynet ops force-local-assignment-refresh-now",
    )?;
    wait_for_daemon_socket(
        identity,
        known_hosts,
        host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )
}

fn install_dns_zone_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        verifier_local,
        target,
        "/tmp/rn-dns-zone.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        bundle_local,
        target,
        "/tmp/rn-dns-zone.bundle",
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
        "install -m 0644 -o root -g root /tmp/rn-dns-zone.pub /etc/rustynet/dns-zone.pub && install -m 0640 -o root -g rustynetd /tmp/rn-dns-zone.bundle /var/lib/rustynet/rustynetd.dns-zone && rm -f /var/lib/rustynet/rustynetd.dns-zone.watermark /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle",
    )
}

fn capture_client_role_snapshot(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
) -> Result<String, String> {
    let status_output = status(identity, known_hosts, host)?;
    let status_line = read_last_matching_line(&status_output, "node_id=");
    if status_line.is_empty() {
        return Ok(status_line);
    }
    let route_output = capture_root(
        identity,
        known_hosts,
        host,
        "ip -4 route get 1.1.1.1 || true",
    )?;
    let route_line = sanitize_line(route_output.trim());
    if route_line.is_empty() {
        Ok(status_line)
    } else {
        Ok(format!("{status_line} route={route_line}"))
    }
}

fn wait_for_role(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    role: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..40 {
        last = status(identity, known_hosts, host)?;
        let status_line = read_last_matching_line(&last, "node_id=");
        if role_runtime_ready(&status_line, role) {
            return Ok(status_line);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(format!(
        "timed out waiting for {host} to reach role {role}: {}",
        read_last_matching_line(&last, "node_id=")
    ))
}

fn role_runtime_ready(status_line: &str, role: &str) -> bool {
    field_value(status_line, "node_role") == role
        && field_value(status_line, "restricted_safe_mode") == "false"
        && field_value(status_line, "state") != "FailClosed"
        && field_value(status_line, "bootstrap_error") == "none"
        && field_value(status_line, "last_reconcile_error") == "none"
}

fn client_exit_route_converged(status_line: &str, expected_exit: &str) -> bool {
    role_runtime_ready(status_line, "client")
        && field_value(status_line, "exit_node") == expected_exit
        && route_uses_rustynet0(status_line)
}

fn route_uses_rustynet0(route: &str) -> bool {
    route.contains("dev rustynet0")
}

fn wait_for_client_exit_route_convergence(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    expected_exit: &str,
) -> Result<String, String> {
    let start = Instant::now();
    let timeout = Duration::from_secs(ROLE_SWITCH_ROUTE_CONVERGENCE_TIMEOUT_SECS);
    let mut last_status = String::new();
    let mut last_route = String::new();
    while start.elapsed() <= timeout {
        last_status = status(identity, known_hosts, host)?;
        let status_line = read_last_matching_line(&last_status, "node_id=");
        let route = capture_root(
            identity,
            known_hosts,
            host,
            "ip -4 route get 1.1.1.1 || true",
        )?;
        last_route = route.trim().to_string();
        let combined = if last_route.is_empty() {
            status_line.clone()
        } else {
            format!("{status_line} route={}", sanitize_line(&last_route))
        };
        if client_exit_route_converged(&combined, expected_exit) {
            return Ok(combined);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "timed out waiting for {host} to restore client route convergence via rustynet0 for exit {expected_exit}: status={} route={}",
        read_last_matching_line(&last_status, "node_id="),
        sanitize_line(&last_route)
    ))
}

fn route_advertise_denied(identity: &Path, known_hosts: &Path, host: &str) -> Result<bool, String> {
    let command = "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 10.250.0.0/16 >/dev/null 2>&1 && exit 1 || exit 0";
    let status = ssh_status(
        identity,
        known_hosts,
        host,
        &format!("sudo -n sh -lc {}", shell_quote(command)),
    )?;
    Ok(status.success())
}

fn exit_select_denied(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    baseline_exit: &str,
) -> Result<bool, String> {
    if baseline_exit.is_empty() || baseline_exit == "none" {
        return Ok(false);
    }
    let command = format!(
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet exit-node select {} >/dev/null 2>&1 && exit 1 || exit 0",
        shell_quote(baseline_exit)
    );
    let status = ssh_status(
        identity,
        known_hosts,
        host,
        &format!("sudo -n sh -lc {}", shell_quote(command.as_str())),
    )?;
    Ok(status.success())
}

fn lan_toggle_denied(identity: &Path, known_hosts: &Path, host: &str) -> Result<bool, String> {
    let command = "env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-lan-access-coupling --enable true --env-path /etc/rustynet/assignment-refresh.env --lan-routes 192.168.1.0/24 >/dev/null 2>&1 && exit 1 || exit 0";
    let status = ssh_status(
        identity,
        known_hosts,
        host,
        &format!("sudo -n sh -lc {}", shell_quote(command)),
    )?;
    Ok(status.success())
}

fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '\t' | '\r' | '\n') {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_role_switch_matrix_test --ssh-identity-file <path> [options]\n\noptions:\n  --exit-host <user@host>\n  --exit-node-id <id>\n  --debian-host <user@host>\n  --debian-node-id <id>\n  --ubuntu-host <user@host>\n  --ubuntu-node-id <id>\n  --fedora-host <user@host>\n  --fedora-node-id <id>\n  --mint-host <user@host>\n  --mint-node-id <id>\n  --ssh-allow-cidrs <cidrs>\n  --report-path <path>\n  --source-path <path>\n  --log-path <path>\n  --known-hosts <path>\n  --git-commit <sha>\n  --traversal-env-file <path>\n  --dns-zone-env-file <path>"
    );
}

fn utc_now_string() -> String {
    let output = Command::new("date")
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
    use super::{
        Config, build_signed_state_refresh_context, client_exit_route_converged,
        role_runtime_ready, route_uses_rustynet0,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn role_runtime_ready_requires_converged_runtime_state() {
        let good = "node_id=client-1 node_role=client state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none";
        assert!(role_runtime_ready(good, "client"));

        let fail_closed = "node_id=client-1 node_role=client state=FailClosed restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none";
        assert!(!role_runtime_ready(fail_closed, "client"));

        let restricted = "node_id=client-1 node_role=client state=ExitActive restricted_safe_mode=true bootstrap_error=none last_reconcile_error=none";
        assert!(!role_runtime_ready(restricted, "client"));

        let reconcile_error = "node_id=client-1 node_role=client state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=backend_error";
        assert!(!role_runtime_ready(reconcile_error, "client"));
    }

    #[test]
    fn role_runtime_ready_requires_matching_role() {
        let status = "node_id=client-1 node_role=admin state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none";
        assert!(role_runtime_ready(status, "admin"));
        assert!(!role_runtime_ready(status, "client"));
    }

    #[test]
    fn route_uses_rustynet0_requires_tunnel_device() {
        assert!(route_uses_rustynet0(
            "1.1.1.1 dev rustynet0 src 100.64.0.2 uid 0"
        ));
        assert!(!route_uses_rustynet0(
            "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.12 uid 0"
        ));
    }

    #[test]
    fn client_exit_route_converged_requires_ready_client_exit_and_route() {
        let good = "node_id=client-1 node_role=client state=ExitActive exit_node=exit-1 restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none route=1.1.1.1 dev rustynet0 src 100.64.0.2 uid 0";
        assert!(client_exit_route_converged(good, "exit-1"));

        let wrong_exit = "node_id=client-1 node_role=client state=ExitActive exit_node=exit-2 restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none route=1.1.1.1 dev rustynet0 src 100.64.0.2 uid 0";
        assert!(!client_exit_route_converged(wrong_exit, "exit-1"));

        let underlay_route = "node_id=client-1 node_role=client state=ExitActive exit_node=exit-1 restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none route=1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.12 uid 0";
        assert!(!client_exit_route_converged(underlay_route, "exit-1"));
    }

    #[test]
    fn signed_state_refresh_context_requires_paired_env_files() {
        let temp_root =
            std::env::temp_dir().join(format!("role-switch-refresh-{}", std::process::id()));
        fs::create_dir_all(&temp_root).expect("temp dir should exist");
        let traversal_env = temp_root.join("issue_traversal.env");
        let dns_zone_env = temp_root.join("issue_dns_zone.env");
        fs::write(&traversal_env, "NODES_SPEC=a\n").expect("write traversal env");
        fs::write(&dns_zone_env, "NODES_SPEC=a\n").expect("write dns env");

        let mut config = Config {
            ssh_identity_file: PathBuf::from("/tmp/key"),
            exit_host: "debian@192.168.64.8".to_string(),
            exit_node_id: "exit-1".to_string(),
            debian_host: "debian@192.168.64.4".to_string(),
            debian_node_id: "client-1".to_string(),
            ubuntu_host: "debian@192.168.64.9".to_string(),
            ubuntu_node_id: "client-2".to_string(),
            fedora_host: "debian@192.168.64.10".to_string(),
            fedora_node_id: "client-3".to_string(),
            mint_host: "debian@192.168.64.11".to_string(),
            mint_node_id: "client-4".to_string(),
            ssh_allow_cidrs: "192.168.64.0/24".to_string(),
            report_path: temp_root.join("report.json"),
            source_path: temp_root.join("source.md"),
            log_path: temp_root.join("role-switch.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
            traversal_env_file: Some(traversal_env.clone()),
            dns_zone_env_file: None,
        };

        let err = build_signed_state_refresh_context(&config)
            .expect_err("missing dns env file must be rejected");
        assert!(err.contains("--dns-zone-env-file"));

        config.dns_zone_env_file = Some(dns_zone_env.clone());
        let refresh = build_signed_state_refresh_context(&config)
            .expect("paired env files should build")
            .expect("refresh context should exist");
        assert_eq!(refresh.targets.len(), 5);
        assert_eq!(refresh.traversal_env_file, traversal_env);
        assert_eq!(refresh.dns_zone_env_file, dns_zone_env);

        let _ = fs::remove_dir_all(&temp_root);
    }
}
