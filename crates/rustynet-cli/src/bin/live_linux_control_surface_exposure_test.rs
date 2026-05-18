#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{LiveLabContext, Logger, read_text, repo_root, run_cargo_ops};

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
                print_usage();
                return Err(format!("unknown command: {other}"));
            }
        }
        idx += 1;
    }

    if ssh_identity_file.is_empty() || client_host.is_empty() {
        print_usage();
        return Err("missing required argument: --ssh-identity-file, --client-host".to_owned());
    }

    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }

    let logger = Logger::new(&log_path)?;
    let ssh_identity_path = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-control-surface", ssh_identity_path.as_path())?;

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
        return Err("missing required argument: at least one target host is required".to_owned());
    }

    for target in &host_targets {
        ctx.push_sudo_password(target)?;
        ctx.wait_for_daemon_socket(target, "/run/rustynet/rustynetd.sock", 20, 2)?;
    }

    for (label, target) in host_labels.iter().zip(host_targets.iter()) {
        logger.line(format!("Inspecting control surfaces on {label} {target}"))?;
        let daemon_socket_meta = ctx.capture_root(
            target,
            &["stat", "-Lc", "%F|%a|%U|%G", "/run/rustynet/rustynetd.sock"],
        )?;
        let helper_socket_meta = ctx.capture_root(
            target,
            &[
                "stat",
                "-Lc",
                "%F|%a|%U|%G",
                "/run/rustynet/rustynetd-privileged.sock",
            ],
        )?;
        let inet_listeners = ctx.capture_root_allow_failure(target, &["ss", "-H", "-ltnup"])?;
        let dns_service_state = ctx.capture_root_allow_failure(
            target,
            &["systemctl", "is-active", "rustynetd-managed-dns.service"],
        )?;
        write_block(
            &ctx.work_dir.join(format!("{label}.daemon_socket.txt")),
            &daemon_socket_meta,
        )?;
        write_block(
            &ctx.work_dir.join(format!("{label}.helper_socket.txt")),
            &helper_socket_meta,
        )?;
        write_block(
            &ctx.work_dir.join(format!("{label}.inet_listeners.txt")),
            &inet_listeners,
        )?;
        write_block(
            &ctx.work_dir.join(format!("{label}.managed_dns_state.txt")),
            &dns_service_state,
        )?;
    }

    let mut remote_dns_probe_status = "skipped".to_owned();
    let mut remote_dns_probe_output = "not-applicable".to_owned();
    let client_dns_state_file = ctx.work_dir.join("client.managed_dns_state.txt");
    if !probe_host.is_empty()
        && probe_host != client_host
        && client_dns_state_file.exists()
        && read_text(&client_dns_state_file)
            .map(|text| text.trim() == "active")
            .unwrap_or(false)
    {
        let client_addr = LiveLabContext::resolved_target_address(&client_host)?;
        let dns_port = dns_bind_addr
            .rsplit_once(':')
            .map_or_else(|| "53535".to_owned(), |(_, port)| port.to_owned());
        remote_dns_probe_output = ctx.capture_root_allow_failure(
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
        )?;
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
            "pass".to_owned()
        } else {
            "fail".to_owned()
        };
    }

    let captured_at_utc = now_utc();
    let captured_at_unix = now_unix();
    let work_dir_string = ctx.work_dir.to_string_lossy().to_string();
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--dns-bind-addr".to_owned(),
        dns_bind_addr.clone(),
        "--remote-dns-probe-status".to_owned(),
        remote_dns_probe_status.clone(),
        "--remote-dns-probe-output".to_owned(),
        remote_dns_probe_output.clone(),
        "--work-dir".to_owned(),
        work_dir_string,
        "--captured-at-utc".to_owned(),
        captured_at_utc,
        "--captured-at-unix".to_owned(),
        captured_at_unix,
    ];
    let mut host_label_args = Vec::new();
    for label in &host_labels {
        host_label_args.push("--host-label".to_owned());
        host_label_args.push(label.clone());
    }
    let mut cargo_args = report_args;
    cargo_args.extend(host_label_args);
    let cargo_refs = cargo_args.iter().map(String::as_str).collect::<Vec<_>>();
    let report_status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-control-surface-report",
        &cargo_refs,
    )?;

    if report_status != "pass" {
        return Err(format!(
            "control-surface exposure test failed; see {}",
            report_path.display()
        ));
    }

    logger.line(format!(
        "Control-surface exposure report written: {}",
        report_path.display()
    ))?;
    Ok(())
}

fn append_host(labels: &mut Vec<String>, targets: &mut Vec<String>, label: &str, target: &str) {
    if !target.is_empty() {
        labels.push(label.to_owned());
        targets.push(target.to_owned());
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    if idx >= args.len() {
        return Err(format!("missing required argument value for {flag}"));
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
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "0".to_owned(),
        |duration| duration.as_secs().to_string(),
    )
}

fn now_utc() -> String {
    now_unix()
}
