#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{LiveLabContext, Logger, repo_root, run_cargo_ops};

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
    let mut client_host = String::new();
    let mut rogue_endpoint_ip = String::new();
    let mut ssh_identity_file = String::new();
    let mut socket_path = String::from("/run/rustynet/rustynetd.sock");
    let mut assignment_path = String::from("/var/lib/rustynet/rustynetd.assignment");
    let mut report_path = root_dir.join("artifacts/phase10/live_linux_endpoint_hijack_report.json");
    let mut log_path = root_dir.join("artifacts/phase10/source/live_linux_endpoint_hijack.log");

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
            "--rogue-endpoint-ip" => {
                idx += 1;
                rogue_endpoint_ip = required_value(&args, idx, "--rogue-endpoint-ip")?;
            }
            "--socket-path" => {
                idx += 1;
                socket_path = required_value(&args, idx, "--socket-path")?;
            }
            "--assignment-path" => {
                idx += 1;
                assignment_path = required_value(&args, idx, "--assignment-path")?;
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

    if ssh_identity_file.is_empty() || client_host.is_empty() || rogue_endpoint_ip.is_empty() {
        print_usage();
        return Err(2);
    }
    rogue_endpoint_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|err| {
            eprintln!("invalid rogue endpoint IPv4 address {rogue_endpoint_ip:?}: {err}");
            2
        })?;

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
    let mut ctx = LiveLabContext::new(
        "rustynet-endpoint-hijack",
        PathBuf::from(&ssh_identity_file).as_path(),
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    ctx.push_sudo_password(&client_host).map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    ctx.wait_for_daemon_socket(&client_host, &socket_path, 20, 2)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let baseline_status_output = ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                "rustynet",
                "status",
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let baseline_netcheck_output = ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                "rustynet",
                "netcheck",
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let baseline_endpoints = ctx
        .capture_root_allow_failure(&client_host, &["wg", "show", "rustynet0", "endpoints"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    if baseline_status_output.contains("state=FailClosed") {
        eprintln!("baseline runtime is already fail-closed; refusing endpoint hijack test");
        return Err(1);
    }

    let mut assignment_timer_was_active = false;
    if ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "systemctl",
                "is-active",
                "rustynetd-assignment-refresh.timer",
            ],
        )
        .map(|state| state.trim() == "active")
        .unwrap_or(false)
    {
        assignment_timer_was_active = true;
    }
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["systemctl", "stop", "rustynetd-assignment-refresh.timer"],
    );
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["systemctl", "stop", "rustynetd-assignment-refresh.service"],
    );

    let backup_path = format!(
        "/var/lib/rustynet/rustynetd.assignment.endpoint-hijack.{}.bak",
        now_unix()
    );
    let mut rollback = EndpointHijackRollback {
        ctx: ctx.clone(),
        client_host: client_host.clone(),
        assignment_path: assignment_path.clone(),
        backup_path: Some(backup_path.clone()),
        watermark_path: "/var/lib/rustynet/rustynetd.assignment.watermark".to_string(),
        timer_was_active: assignment_timer_was_active,
    };

    ctx.run_root(&client_host, &["cp", &assignment_path, &backup_path])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    ctx.run_root(
        &client_host,
        &[
            "rustynet",
            "ops",
            "rewrite-assignment-peer-endpoint-ip",
            "--assignment-path",
            &assignment_path,
            "--endpoint-ip",
            &rogue_endpoint_ip,
        ],
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.assignment.watermark",
        ],
    );
    ctx.run_root(&client_host, &["systemctl", "restart", "rustynetd.service"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    ctx.wait_for_daemon_socket(&client_host, &socket_path, 20, 1)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let status_after_hijack = ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                "rustynet",
                "status",
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let netcheck_after_hijack = ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                "rustynet",
                "netcheck",
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let endpoints_after_hijack = ctx
        .capture_root_allow_failure(&client_host, &["wg", "show", "rustynet0", "endpoints"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    ctx.run_root(&client_host, &["cp", &backup_path, &assignment_path])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &[
            "rm",
            "-f",
            &backup_path,
            "/var/lib/rustynet/rustynetd.assignment.watermark",
        ],
    );
    ctx.run_root(&client_host, &["systemctl", "restart", "rustynetd.service"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    rollback.backup_path = None;
    std::thread::sleep(std::time::Duration::from_secs(3));
    ctx.wait_for_daemon_socket(&client_host, &socket_path, 20, 1)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    if assignment_timer_was_active {
        let _ = ctx.run_root_allow_failure(
            &client_host,
            &["systemctl", "start", "rustynetd-assignment-refresh.timer"],
        );
    }

    let status_after_recovery = ctx
        .capture_root_allow_failure(
            &client_host,
            &[
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                "rustynet",
                "status",
            ],
        )
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    let endpoints_after_recovery = ctx
        .capture_root_allow_failure(&client_host, &["wg", "show", "rustynet0", "endpoints"])
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    logger
        .block("Baseline status", &baseline_status_output)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Baseline netcheck", &baseline_netcheck_output)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Baseline endpoints", &baseline_endpoints)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Status after hijack", &status_after_hijack)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Netcheck after hijack", &netcheck_after_hijack)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Endpoints after hijack", &endpoints_after_hijack)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Status after recovery", &status_after_recovery)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    logger
        .block("Endpoints after recovery", &endpoints_after_recovery)
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;

    let captured_at_utc = now_utc();
    let captured_at_unix = now_unix();
    let report_args = vec![
        "--report-path".to_string(),
        report_path.to_string_lossy().to_string(),
        "--rogue-endpoint-ip".to_string(),
        rogue_endpoint_ip.clone(),
        "--baseline-status".to_string(),
        baseline_status_output.clone(),
        "--baseline-netcheck".to_string(),
        baseline_netcheck_output.clone(),
        "--baseline-endpoints".to_string(),
        baseline_endpoints.clone(),
        "--status-after-hijack".to_string(),
        status_after_hijack.clone(),
        "--netcheck-after-hijack".to_string(),
        netcheck_after_hijack.clone(),
        "--endpoints-after-hijack".to_string(),
        endpoints_after_hijack.clone(),
        "--status-after-recovery".to_string(),
        status_after_recovery.clone(),
        "--endpoints-after-recovery".to_string(),
        endpoints_after_recovery.clone(),
        "--captured-at-utc".to_string(),
        captured_at_utc,
        "--captured-at-unix".to_string(),
        captured_at_unix,
    ];
    let report_refs = report_args.iter().map(String::as_str).collect::<Vec<_>>();
    let report_status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-endpoint-hijack-report",
        &report_refs,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if report_status != "pass" {
        eprintln!("endpoint hijack test failed; see {}", report_path.display());
        return Err(1);
    }

    logger
        .line(format!(
            "Endpoint hijack report written: {}",
            report_path.display()
        ))
        .map_err(|err| {
            eprintln!("{err}");
            1
        })?;
    Ok(())
}

struct EndpointHijackRollback {
    ctx: LiveLabContext,
    client_host: String,
    assignment_path: String,
    backup_path: Option<String>,
    watermark_path: String,
    timer_was_active: bool,
}

impl Drop for EndpointHijackRollback {
    fn drop(&mut self) {
        let Some(backup_path) = self.backup_path.as_ref() else {
            return;
        };
        let _ = self.ctx.run_root_allow_failure(
            &self.client_host,
            &["cp", backup_path, &self.assignment_path],
        );
        let _ = self.ctx.run_root_allow_failure(
            &self.client_host,
            &["rm", "-f", backup_path, &self.watermark_path],
        );
        let _ = self.ctx.run_root_allow_failure(
            &self.client_host,
            &["systemctl", "restart", "rustynetd.service"],
        );
        if self.timer_was_active {
            let _ = self.ctx.run_root_allow_failure(
                &self.client_host,
                &["systemctl", "start", "rustynetd-assignment-refresh.timer"],
            );
        }
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
        "usage: live_linux_endpoint_hijack_test.sh --ssh-identity-file <path> --client-host <user@host> --rogue-endpoint-ip <ipv4> [options]"
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
