#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{LiveLabContext, Logger, read_text, repo_root, run_cargo_ops};

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

    let mut exit_host = String::new();
    let mut client_host = String::new();
    let mut entry_host = String::new();
    let mut aux_host = String::new();
    let mut extra_host = String::new();
    let mut probe_host = String::new();
    let mut ssh_identity_file = String::new();
    let mut dns_bind_addr = String::from("127.0.0.1:53535");
    let mut report_path =
        root_dir.join("artifacts/phase10/live_linux_control_surface_exposure_report.json");
    let mut log_path =
        root_dir.join("artifacts/phase10/source/live_linux_control_surface_exposure.log");

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
            "--entry-host" => {
                idx += 1;
                entry_host = required_value(&args, idx, "--entry-host")?;
            }
            "--aux-host" => {
                idx += 1;
                aux_host = required_value(&args, idx, "--aux-host")?;
            }
            "--extra-host" => {
                idx += 1;
                extra_host = required_value(&args, idx, "--extra-host")?;
            }
            "--probe-host" => {
                idx += 1;
                probe_host = required_value(&args, idx, "--probe-host")?;
            }
            "--dns-bind-addr" => {
                idx += 1;
                dns_bind_addr = required_value(&args, idx, "--dns-bind-addr")?;
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

    if ssh_identity_file.is_empty() || client_host.is_empty() {
        print_usage();
        return Err(2);
    }

    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            eprintln!("failed to create {}: {err}", parent.display());
            1
        })?;
    }
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            eprintln!("failed to create {}: {err}", parent.display());
            1
        })?;
    }

    let logger = Logger::new(&log_path).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let ssh_identity_path = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-control-surface", ssh_identity_path.as_path())
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    if probe_host.is_empty() {
        if !exit_host.is_empty() && exit_host != client_host {
            probe_host = exit_host.clone();
        } else if !entry_host.is_empty() && entry_host != client_host {
            probe_host = entry_host.clone();
        } else if !aux_host.is_empty() && aux_host != client_host {
            probe_host = aux_host.clone();
        } else if !extra_host.is_empty() && extra_host != client_host {
            probe_host = extra_host.clone();
        }
    }

    let mut host_labels = Vec::new();
    let mut host_targets = Vec::new();
    append_host(&mut host_labels, &mut host_targets, "exit", &exit_host);
    append_host(&mut host_labels, &mut host_targets, "client", &client_host);
    append_host(&mut host_labels, &mut host_targets, "entry", &entry_host);
    append_host(&mut host_labels, &mut host_targets, "aux", &aux_host);
    append_host(&mut host_labels, &mut host_targets, "extra", &extra_host);

    if host_targets.is_empty() {
        eprintln!("at least one target host is required");
        return Err(2);
    }

    for target in &host_targets {
        ctx.push_sudo_password(target).map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
    }

    for (label, target) in host_labels.iter().zip(host_targets.iter()) {
        logger
            .line(format!("Inspecting control surfaces on {label} {target}"))
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        let daemon_socket_meta = ctx
            .capture_root(
                target,
                &["stat", "-Lc", "%F|%a|%U|%G", "/run/rustynet/rustynetd.sock"],
            )
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        let helper_socket_meta = ctx
            .capture_root(
                target,
                &[
                    "stat",
                    "-Lc",
                    "%F|%a|%U|%G",
                    "/run/rustynet/rustynetd-privileged.sock",
                ],
            )
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        let inet_listeners = ctx
            .capture_root_allow_failure(target, &["ss", "-H", "-ltnup"])
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        let dns_service_state = ctx
            .capture_root_allow_failure(
                target,
                &["systemctl", "is-active", "rustynetd-managed-dns.service"],
            )
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        write_block(
            &ctx.work_dir.join(format!("{label}.daemon_socket.txt")),
            &daemon_socket_meta,
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        write_block(
            &ctx.work_dir.join(format!("{label}.helper_socket.txt")),
            &helper_socket_meta,
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        write_block(
            &ctx.work_dir.join(format!("{label}.inet_listeners.txt")),
            &inet_listeners,
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        write_block(
            &ctx.work_dir.join(format!("{label}.managed_dns_state.txt")),
            &dns_service_state,
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    }

    let mut remote_dns_probe_status = "skipped".to_string();
    let mut remote_dns_probe_output = "not-applicable".to_string();
    let client_dns_state_file = ctx.work_dir.join("client.managed_dns_state.txt");
    if !probe_host.is_empty()
        && probe_host != client_host
        && client_dns_state_file.exists()
        && read_text(&client_dns_state_file)
            .map(|text| text.trim() == "active")
            .unwrap_or(false)
    {
        let client_addr = LiveLabContext::resolved_target_address(&client_host).map_err(|err| {
            eprintln!("{err}");
            1
        })?;
        let dns_port = dns_bind_addr
            .rsplit_once(':')
            .map(|(_, port)| port.to_string())
            .unwrap_or_else(|| "53535".to_string());
        remote_dns_probe_output = ctx
            .capture_root_allow_failure(
                &probe_host,
                &[
                    "rustynet",
                    "ops",
                    "e2e-dns-query",
                    "--server",
                    &client_addr,
                    "--port",
                    &dns_port,
                    "--qname",
                    "blocked-probe.rustynet",
                    "--timeout-ms",
                    "1000",
                ],
            )
            .map_err(|err| {
                eprintln!("{err}");
                1
            })?;
        let blocked_probe = ctx
            .run_root(
                &probe_host,
                &[
                    "rustynet",
                    "ops",
                    "e2e-dns-query",
                    "--server",
                    &client_addr,
                    "--port",
                    &dns_port,
                    "--qname",
                    "blocked-probe.rustynet",
                    "--timeout-ms",
                    "1000",
                    "--fail-on-no-response",
                ],
            )
            .is_err();
        remote_dns_probe_status = if blocked_probe {
            "pass".to_string()
        } else {
            "fail".to_string()
        };
    }

    let captured_at_utc = now_utc();
    let captured_at_unix = now_unix();
    let work_dir_string = ctx.work_dir.to_string_lossy().to_string();
    let report_args = vec![
        "--report-path".to_string(),
        report_path.to_string_lossy().to_string(),
        "--dns-bind-addr".to_string(),
        dns_bind_addr.clone(),
        "--remote-dns-probe-status".to_string(),
        remote_dns_probe_status.clone(),
        "--remote-dns-probe-output".to_string(),
        remote_dns_probe_output.clone(),
        "--work-dir".to_string(),
        work_dir_string,
        "--captured-at-utc".to_string(),
        captured_at_utc,
        "--captured-at-unix".to_string(),
        captured_at_unix,
    ];
    let mut host_label_args = Vec::new();
    for label in &host_labels {
        host_label_args.push("--host-label".to_string());
        host_label_args.push(label.clone());
    }
    let mut cargo_args = report_args;
    cargo_args.extend(host_label_args);
    let cargo_refs = cargo_args.iter().map(String::as_str).collect::<Vec<_>>();
    let report_status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-control-surface-report",
        &cargo_refs,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    if report_status != "pass" {
        eprintln!(
            "control-surface exposure test failed; see {}",
            report_path.display()
        );
        return Err(1);
    }

    logger
        .line(format!(
            "Control-surface exposure report written: {}",
            report_path.display()
        ))
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    Ok(())
}

fn append_host(labels: &mut Vec<String>, targets: &mut Vec<String>, label: &str, target: &str) {
    if !target.is_empty() {
        labels.push(label.to_string());
        targets.push(target.to_string());
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
    println!(
        "usage: live_linux_control_surface_exposure_test.sh --ssh-identity-file <path> --client-host <user@host> [options]"
    );
}

fn write_block(path: &PathBuf, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn now_unix() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn now_utc() -> String {
    now_unix()
}
