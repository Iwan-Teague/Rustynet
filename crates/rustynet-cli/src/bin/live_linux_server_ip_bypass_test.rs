#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{LiveLabContext, Logger, parse_ipv4, repo_root, run_cargo_ops};

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
    let mut client_host = String::new();
    let mut probe_host = String::new();
    let mut probe_bind_ip = String::new();
    let mut ssh_identity_file = String::new();
    let mut ssh_allow_cidrs = String::from("192.168.18.0/24");
    let mut probe_port = String::from("18080");
    let mut report_path =
        root_dir.join("artifacts/phase10/live_linux_server_ip_bypass_report.json");
    let mut log_path = root_dir.join("artifacts/phase10/source/live_linux_server_ip_bypass.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = required_value(&args, idx, "--ssh-identity-file")?;
            }
            "--client-host" => {
                idx += 1;
                client_host = required_value(&args, idx, "--client-host")?;
            }
            "--probe-host" => {
                idx += 1;
                probe_host = required_value(&args, idx, "--probe-host")?;
            }
            "--probe-bind-ip" => {
                idx += 1;
                probe_bind_ip = required_value(&args, idx, "--probe-bind-ip")?;
            }
            "--ssh-allow-cidrs" => {
                idx += 1;
                ssh_allow_cidrs = required_value(&args, idx, "--ssh-allow-cidrs")?;
            }
            "--probe-port" => {
                idx += 1;
                probe_port = required_value(&args, idx, "--probe-port")?;
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

    if ssh_identity_file.is_empty() || client_host.is_empty() || probe_host.is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-identity-file, --client-host, --probe-host"
                .to_string(),
        );
    }
    if client_host == probe_host {
        return Err("invalid path: --client-host and --probe-host must differ".to_string());
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
    let mut ctx = LiveLabContext::new("rustynet-server-ip-bypass", ssh_identity_path.as_path())?;

    let probe_ip = if probe_bind_ip.is_empty() {
        LiveLabContext::resolved_target_address(&probe_host)?
    } else {
        parse_ipv4(&probe_bind_ip, "probe bind ip")?.to_string()
    };
    let probe_pid_path = "/tmp/rn-underlay-http-server.pid".to_string();
    let probe_log_path = "/tmp/rn-underlay-http-server.log".to_string();
    let _cleanup = ProbeCleanup {
        ctx: ctx.clone(),
        host: probe_host.clone(),
        pid_path: probe_pid_path.clone(),
        log_path: probe_log_path.clone(),
    };

    ctx.push_sudo_password(&client_host)?;
    ctx.push_sudo_password(&probe_host)?;
    ctx.wait_for_daemon_socket(&client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    ctx.wait_for_daemon_socket(&probe_host, "/run/rustynet/rustynetd.sock", 20, 2)?;

    logger.line(format!(
        "Starting underlay HTTP probe service on {probe_host} ({probe_ip}:{probe_port})"
    ))?;
    start_probe_server(
        &ctx,
        &probe_host,
        &probe_ip,
        &probe_port,
        &probe_pid_path,
        &probe_log_path,
    )?;
    ctx.retry_root(
        &probe_host,
        &[
            "rustynet",
            "ops",
            "e2e-http-probe-client",
            "--host",
            &probe_ip,
            "--port",
            &probe_port,
            "--timeout-ms",
            "2000",
            "--expect-marker",
            "probe-ok",
        ],
        15,
        1,
    )?;

    let client_status = ctx.capture_root(&client_host, &["rustynet", "status"])?;
    let client_internet_route = ctx
        .capture(&client_host, &["ip", "-4", "route", "get", "1.1.1.1"])
        .unwrap_or_default();
    let client_probe_route = ctx
        .capture(&client_host, &["ip", "-4", "route", "get", &probe_ip])
        .unwrap_or_default();
    let client_table_51820 = ctx
        .capture(
            &client_host,
            &["ip", "-4", "route", "show", "table", "51820"],
        )
        .unwrap_or_default();
    let client_endpoints = ctx
        .capture_root(&client_host, &["wg", "show", "rustynet0", "endpoints"])
        .unwrap_or_default();
    let probe_self_test = ctx.capture_root_allow_failure(
        &probe_host,
        &[
            "rustynet",
            "ops",
            "e2e-http-probe-client",
            "--host",
            &probe_ip,
            "--port",
            &probe_port,
            "--timeout-ms",
            "2000",
            "--expect-marker",
            "probe-ok",
        ],
    )?;
    let probe_from_client_output = ctx.capture_root_allow_failure(
        &client_host,
        &[
            "rustynet",
            "ops",
            "e2e-http-probe-client",
            "--host",
            &probe_ip,
            "--port",
            &probe_port,
            "--timeout-ms",
            "2000",
            "--expect-marker",
            "probe-ok",
        ],
    )?;
    let probe_from_client_status = if ctx
        .run_root(
            &client_host,
            &[
                "rustynet",
                "ops",
                "e2e-http-probe-client",
                "--host",
                &probe_ip,
                "--port",
                &probe_port,
                "--timeout-ms",
                "2000",
                "--expect-marker",
                "probe-ok",
            ],
        )
        .is_ok()
    {
        "fail"
    } else {
        "pass"
    };

    logger.block("Client status", &client_status)?;
    logger.block("Client route to internet", &client_internet_route)?;
    logger.block(
        "Client route to probe host underlay IP",
        &client_probe_route,
    )?;
    logger.block("Client table 51820", &client_table_51820)?;
    logger.block("Client endpoints", &client_endpoints)?;
    logger.block("Probe host self-test output", &probe_self_test)?;
    logger.block("Client probe output", &probe_from_client_output)?;

    let captured_at_utc = now_utc();
    let captured_at_unix = now_unix();
    let report_args = vec![
        "--report-path".to_string(),
        report_path.to_string_lossy().to_string(),
        "--allowed-management-cidrs".to_string(),
        ssh_allow_cidrs.clone(),
        "--probe-from-client-status".to_string(),
        probe_from_client_status.to_string(),
        "--probe-ip".to_string(),
        probe_ip.clone(),
        "--probe-port".to_string(),
        probe_port.clone(),
        "--client-internet-route".to_string(),
        client_internet_route.clone(),
        "--client-probe-route".to_string(),
        client_probe_route.clone(),
        "--client-table-51820".to_string(),
        client_table_51820.clone(),
        "--client-endpoints".to_string(),
        client_endpoints.clone(),
        "--probe-self-test".to_string(),
        probe_self_test.clone(),
        "--probe-from-client-output".to_string(),
        probe_from_client_output.clone(),
        "--captured-at-utc".to_string(),
        captured_at_utc,
        "--captured-at-unix".to_string(),
        captured_at_unix,
    ];
    let report_refs = report_args.iter().map(String::as_str).collect::<Vec<_>>();
    let report_status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-server-ip-bypass-report",
        &report_refs,
    )?;

    if report_status != "pass" {
        return Err(format!(
            "server-IP bypass test failed; see {}",
            report_path.display()
        ));
    }

    logger.line(format!(
        "Server-IP bypass report written: {}",
        report_path.display()
    ))?;
    Ok(())
}

struct ProbeCleanup {
    ctx: LiveLabContext,
    host: String,
    pid_path: String,
    log_path: String,
}

impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        if let Ok(pid_text) = self
            .ctx
            .capture_root_allow_failure(&self.host, &["cat", &self.pid_path])
            && let Ok(pid) = pid_text.trim().parse::<i32>()
        {
            let pid_string = pid.to_string();
            let _ = self
                .ctx
                .run_root_allow_failure(&self.host, &["kill", &pid_string]);
        }
        let _ = self
            .ctx
            .run_root_allow_failure(&self.host, &["rm", "-f", &self.pid_path, &self.log_path]);
    }
}

fn start_probe_server(
    ctx: &LiveLabContext,
    host: &str,
    probe_ip: &str,
    probe_port: &str,
    probe_pid_path: &str,
    probe_log_path: &str,
) -> Result<(), String> {
    let shell_command = format!(
        "nohup rustynet ops e2e-http-probe-server --bind-ip {} --port {} --response-body {} >{} 2>&1 </dev/null & echo $! > {}",
        live_lab_support::shell_single_quote(probe_ip),
        live_lab_support::shell_single_quote(probe_port),
        live_lab_support::shell_single_quote("probe-ok"),
        live_lab_support::shell_single_quote(probe_log_path),
        live_lab_support::shell_single_quote(probe_pid_path),
    );
    live_lab_support::run_remote_shell(ctx, host, &shell_command).map(|_| ())
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    if idx >= args.len() {
        return Err(format!("missing required argument value for {flag}"));
    }
    Ok(args[idx].clone())
}

fn print_usage() {
    println!(
        "usage: live_linux_server_ip_bypass_test.sh --ssh-identity-file <path> --client-host <user@host> --probe-host <user@host> [options]"
    );
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
