#![forbid(unsafe_code)]

mod live_lab_bin_support;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, capture_root, create_workspace, enforce_host, field_value, git_head_commit,
    read_last_matching_line, remote_src_dir, require_command, run_cargo_ops, shell_quote,
    ssh_status, status, unix_now, wait_for_daemon_socket, write_file,
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

    let pinned_known_hosts = match config.pinned_known_hosts_file {
        Some(path) => path,
        None => live_lab_support::load_home_known_hosts_path()?,
    };
    live_lab_support::ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("role-switch-live")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    live_lab_support::seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;
    let mut logger = Logger::new(&config.log_path)?;
    let mut source_body = String::new();
    let git_commit = config.git_commit.unwrap_or_else(|| {
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

    let mut overall_status = "pass".to_string();
    for (host, os_id, temp_role, node_id) in [
        (
            &config.debian_host,
            "debian13",
            "admin",
            &config.debian_node_id,
        ),
        (
            &config.fedora_host,
            "fedora",
            "blind_exit",
            &config.fedora_node_id,
        ),
        (
            &config.ubuntu_host,
            "ubuntu",
            "admin",
            &config.ubuntu_node_id,
        ),
        (&config.mint_host, "mint", "admin", &config.mint_node_id),
    ] {
        process_host(
            &mut logger,
            &work_known_hosts,
            &config.ssh_identity_file,
            host,
            os_id,
            temp_role,
            node_id,
            &config.ssh_allow_cidrs,
            &tmp_json,
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
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            ssh_identity_file: PathBuf::new(),
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
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?)
                }
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
        Ok(config)
    }
}

#[allow(clippy::too_many_arguments)]
fn process_host(
    logger: &mut Logger,
    known_hosts: &Path,
    identity: &Path,
    host: &str,
    os_id: &str,
    temp_role: &str,
    node_id: &str,
    ssh_allow_cidrs: &str,
    hosts_json_path: &Path,
    source_body: &mut String,
    overall_status: &mut String,
) -> Result<(), String> {
    logger.line(format!("[role-switch] {os_id} {host} -> {temp_role}").as_str())?;
    switch_role(
        identity,
        known_hosts,
        host,
        "client",
        node_id,
        ssh_allow_cidrs,
    )?;
    wait_for_role(identity, known_hosts, host, "client")?;
    let baseline = status(identity, known_hosts, host)?;
    let baseline_exit = field_value(&baseline, "exit_node");

    switch_role(
        identity,
        known_hosts,
        host,
        temp_role,
        node_id,
        ssh_allow_cidrs,
    )?;
    let after_temp = wait_for_role(identity, known_hosts, host, temp_role)?;

    let mut switch_execution = "fail";
    let mut post_switch_reconcile = "fail";
    let mut policy_still_enforced = "fail";
    let mut least_privilege_preserved = "fail";

    if temp_role == "blind_exit" {
        if route_advertise_denied(identity, known_hosts, host)? {
            policy_still_enforced = "pass";
        }
        if exit_select_denied(identity, known_hosts, host, &baseline_exit)?
            && lan_toggle_denied(identity, known_hosts, host)?
        {
            least_privilege_preserved = "pass";
        }
    } else if route_advertise_denied(identity, known_hosts, host)? {
        policy_still_enforced = "pass";
        least_privilege_preserved = "pass";
    }

    switch_role(
        identity,
        known_hosts,
        host,
        "client",
        node_id,
        ssh_allow_cidrs,
    )?;
    let after_restore = wait_for_role(identity, known_hosts, host, "client")?;

    if field_value(&after_temp, "node_role") == temp_role
        && field_value(&after_restore, "node_role") == "client"
    {
        switch_execution = "pass";
    }

    if temp_role == "blind_exit" {
        if field_value(&after_temp, "serving_exit_node") == "true"
            && field_value(&after_temp, "exit_node") == "none"
            && field_value(&after_temp, "lan_access") == "off"
            && !baseline_exit.is_empty()
            && baseline_exit != "none"
            && field_value(&after_restore, "exit_node") == baseline_exit
            && route_via_rustynet0(identity, known_hosts, host)?
        {
            post_switch_reconcile = "pass";
        }
    } else if !baseline_exit.is_empty()
        && baseline_exit != "none"
        && field_value(&after_temp, "serving_exit_node") == "false"
        && field_value(&after_temp, "exit_node") == baseline_exit
        && field_value(&after_restore, "exit_node") == baseline_exit
        && route_via_rustynet0(identity, known_hosts, host)?
    {
        post_switch_reconcile = "pass";
    }

    source_body.push_str(format!("## {os_id} ({host})\n").as_str());
    source_body.push_str(format!("- baseline: {}\n", sanitize_line(&baseline)).as_str());
    source_body.push_str(format!("- after_temp: {}\n", sanitize_line(&after_temp)).as_str());
    source_body
        .push_str(format!("- after_restore: {}\n\n", sanitize_line(&after_restore)).as_str());

    run_cargo_ops(
        &live_lab_support::repo_root()?,
        "update-role-switch-host-result",
        &[
            OsString::from("--hosts-json-path"),
            hosts_json_path.as_os_str().to_os_string(),
            OsString::from("--os-id"),
            OsString::from(os_id),
            OsString::from("--temp-role"),
            OsString::from(temp_role),
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

fn wait_for_role(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    role: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..40 {
        last = status(identity, known_hosts, host)?;
        if field_value(&read_last_matching_line(&last, "node_id="), "node_role") == role {
            return Ok(read_last_matching_line(&last, "node_id="));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(format!(
        "timed out waiting for {host} to reach role {role}: {}",
        read_last_matching_line(&last, "node_id=")
    ))
}

fn route_via_rustynet0(identity: &Path, known_hosts: &Path, host: &str) -> Result<bool, String> {
    let route = capture_root(
        identity,
        known_hosts,
        host,
        "ip -4 route get 1.1.1.1 || true",
    )?;
    Ok(route.contains("dev rustynet0"))
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

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_role_switch_matrix_test --ssh-identity-file <path> [options]\n\noptions:\n  --debian-host <user@host>\n  --debian-node-id <id>\n  --ubuntu-host <user@host>\n  --ubuntu-node-id <id>\n  --fedora-host <user@host>\n  --fedora-node-id <id>\n  --mint-host <user@host>\n  --mint-node-id <id>\n  --ssh-allow-cidrs <cidrs>\n  --report-path <path>\n  --source-path <path>\n  --log-path <path>\n  --known-hosts <path>\n  --git-commit <sha>"
    );
}

fn utc_now_string() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
    }
    "1970-01-01T00:00:00Z".to_string()
}
