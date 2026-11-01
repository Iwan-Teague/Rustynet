#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{LiveLabContext, Logger, read_text, repo_root};
use rustynet_cli::ops_control_surface_expected_set;

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
    // CS4 (OWNER MUST APPROVE the check redefinition): opt-in exact
    // expected-listener-set check. OFF by default; CLI flag ONLY — there is
    // deliberately no environment-variable switch (CS4 fix: an env var is
    // invisible in the lab recipe and can flip a security check on by
    // accident). The shipped check is unchanged unless --expected-listener-set
    // is given, and even then its result stays load-bearing (see below).
    let mut expected_listener_set = false;
    let mut expect_gossip_scope_table = false;
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
            "--expected-listener-set" => {
                expected_listener_set = true;
            }
            "--expect-gossip-scope-table" => {
                expect_gossip_scope_table = true;
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

    let mut expected_set_evidence: Vec<ExpectedSetCapture> = Vec::new();
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
        if expected_listener_set {
            expected_set_evidence.push(capture_expected_set_evidence(
                &ctx,
                label,
                target,
                &inet_listeners,
                expect_gossip_scope_table,
            )?);
        }
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
                live_lab_support::REMOTE_RUSTYNET_BIN,
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
                    live_lab_support::REMOTE_RUSTYNET_BIN,
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
    // In-process, not `cargo run … ops …`: the subprocess built a
    // default-feature binary lacking this `vm-lab`-gated verb, so the write
    // failed with `unknown ops subcommand` and the stage recorded FAIL after
    // its assertions had already passed.
    //
    // `captured_at_unix` is parsed here because the local `now_unix()` returns
    // a String (it renders "0" on a clock error). The typed config wants u64,
    // and mapping a bad value to 0 preserves that existing fallback rather than
    // failing a security stage on a clock read.
    let report_status =
        rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_control_surface_report(
            rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxControlSurfaceReportConfig {
                report_path: report_path.clone(),
                dns_bind_addr: dns_bind_addr.clone(),
                remote_dns_probe_status: remote_dns_probe_status.clone(),
                remote_dns_probe_output: remote_dns_probe_output.clone(),
                work_dir: ctx.work_dir.clone(),
                host_labels: host_labels.clone(),
                captured_at_utc,
                captured_at_unix: captured_at_unix.parse::<u64>().unwrap_or(0),
            },
        )?;

    if expected_listener_set {
        // OPT-IN redefinition (owner approval required): the verdict is the
        // exact expected-listener-set check AND the shipped check. The
        // shipped report decides too (CS4 fix): a perfect listener set must
        // not mask a bad daemon/helper socket mode or a failed remote-DNS
        // probe. `report_status` ("pass"/"fail" of the primary report) is
        // already available; the detailed per-check gate reads the primary
        // report JSON that was just written.
        let options = ops_control_surface_expected_set::ExpectedSetOptions {
            expect_gossip_scope_table,
        };
        let mut verdicts = Vec::new();
        for capture in &expected_set_evidence {
            let probe = run_underlay_probe(&ctx, capture, &probe_host);
            let mut evidence = capture.evidence.clone();
            evidence.underlay_probe = probe;
            verdicts.push(ops_control_surface_expected_set::evaluate_host(
                &evidence,
                &dns_bind_addr,
                options,
            ));
        }
        let expected_report = ops_control_surface_expected_set::render_report(
            &verdicts,
            &dns_bind_addr,
            options,
            captured_at_unix.parse::<u64>().unwrap_or(0),
        );
        let expected_path = report_path.with_extension("expected_set.json");
        write_block(
            &expected_path,
            &serde_json::to_string_pretty(&expected_report)
                .map_err(|err| format!("serialize expected-set report failed: {err}"))?,
        )?;
        for verdict in &verdicts {
            logger.line(format!(
                "expected-listener-set {}: {} {:?}",
                verdict.label,
                if verdict.pass { "pass" } else { "FAIL" },
                verdict.reasons
            ))?;
        }
        // Gate on the CONJUNCTION (D4/CS4): the shipped checks from the
        // primary report (fail closed on any missing field/host) AND the
        // expected-set report's own status. The decision lives in one pure,
        // unit-tested function.
        let verdict = match std::fs::read_to_string(&report_path)
            .map_err(|err| format!("read primary report {}: {err}", report_path.display()))
            .and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .map_err(|err| format!("parse primary report {}: {err}", report_path.display()))
            }) {
            Ok(report) => ops_control_surface_expected_set::combined_verdict(
                &expected_report,
                &ops_control_surface_expected_set::shipped_check_gate_defects(
                    &report,
                    &host_labels,
                ),
            ),
            Err(why) => Err(vec![why]),
        };
        if let Err(failures) = verdict {
            return Err(format!(
                "control-surface expected-listener-set check failed: {failures:?}; see {} and {}",
                expected_path.display(),
                report_path.display()
            ));
        }
        logger.line(format!(
            "Expected-listener-set report written: {} (shipped-check status was {report_status})",
            expected_path.display()
        ))?;
        return Ok(());
    }

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

/// One node's CS4 capture plus the target address the underlay probe needs.
struct ExpectedSetCapture {
    target: String,
    evidence: ops_control_surface_expected_set::HostEvidence,
}

const REMOTE_MEMBERSHIP_SNAPSHOT: &str = "/var/lib/rustynet/membership.snapshot";
const REMOTE_MEMBERSHIP_LOG: &str = "/var/lib/rustynet/membership.log";

/// Capture, in the SAME ssh session set as the `ss` listing, everything the
/// expected-listener-set check judges against: the daemon's own status
/// (backend + gossip state + node id), the `rustynet0` IPv4, the signed
/// anchor list, and (optionally) the CS3 gossip scope table. A capture that
/// cannot run yields empty text, which the evaluator fails closed on.
fn capture_expected_set_evidence(
    ctx: &LiveLabContext,
    label: &str,
    target: &str,
    ss_output: &str,
    capture_scope_table: bool,
) -> Result<ExpectedSetCapture, String> {
    let status_text =
        ctx.capture_root_allow_failure(target, &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"])?;
    let rustynet0_addr_output = ctx.capture_root_allow_failure(
        target,
        &["ip", "-4", "-o", "addr", "show", "dev", "rustynet0"],
    )?;
    let anchor_list_output = ctx.capture_root_allow_failure(
        target,
        &[
            live_lab_support::REMOTE_RUSTYNET_BIN,
            "anchor",
            "list",
            "--snapshot",
            REMOTE_MEMBERSHIP_SNAPSHOT,
            "--log",
            REMOTE_MEMBERSHIP_LOG,
        ],
    )?;
    let gossip_scope_table_output = if capture_scope_table {
        Some(ctx.capture_root_allow_failure(
            target,
            &[
                "nft",
                "list",
                "table",
                "inet",
                ops_control_surface_expected_set::GOSSIP_SCOPE_TABLE,
            ],
        )?)
    } else {
        None
    };
    Ok(ExpectedSetCapture {
        target: target.to_owned(),
        evidence: ops_control_surface_expected_set::HostEvidence {
            label: label.to_owned(),
            ss_output: ss_output.to_owned(),
            status_text,
            rustynet0_addr_output,
            anchor_list_output,
            gossip_scope_table_output,
            underlay_probe: None,
        },
    })
}

/// Active probe from `probe_host` to this node's UNDERLAY address: TCP/51822
/// must not connect, UDP/51821 must not answer, and the TCP/22 (sshd)
/// positive control MUST answer — the lab cannot run without ssh, so a
/// silent control means the probe harness itself is broken and every
/// `no_answer` is vacuous. `None` when there is no peer to probe from
/// (reported as skipped, never as a pass). The address is parsed as an IP
/// before it reaches a command line.
fn run_underlay_probe(
    ctx: &LiveLabContext,
    capture: &ExpectedSetCapture,
    probe_host: &str,
) -> Option<ops_control_surface_expected_set::UnderlayProbe> {
    use ops_control_surface_expected_set::{ProbeOutcome, UnderlayProbe};
    if probe_host.is_empty() || probe_host == capture.target {
        return None;
    }
    let underlay_ip = LiveLabContext::resolved_target_address(&capture.target).ok()?;
    underlay_ip.parse::<std::net::IpAddr>().ok()?;
    let run = |script: &str| -> ProbeOutcome {
        ctx.capture_root_allow_failure(probe_host, &["bash", "-c", script, "cs4", &underlay_ip])
            .map_or(ProbeOutcome::Inconclusive, |out| ProbeOutcome::parse(&out))
    };
    let tcp = run(
        "if timeout 3 bash -c \"exec 3<>/dev/tcp/$1/51822\" >/dev/null 2>&1; then echo answered; else echo no_answer; fi",
    );
    let udp = run(
        "command -v socat >/dev/null 2>&1 || { echo tool_missing; exit 0; }; out=$(printf cs4-probe | timeout 4 socat -t2 - \"UDP4:$1:51821\" 2>/dev/null || true); if [ -n \"$out\" ]; then echo answered; else echo no_answer; fi",
    );
    // Positive control: tcp/22 to the SAME node. The lab's own ssh session
    // proves sshd is up, so `no_answer`/`inconclusive` here indicts the
    // probe plumbing (missing `timeout`, no /dev/tcp, capture failure), not
    // the node's exposure.
    let control = run(
        "if timeout 3 bash -c \"exec 3<>/dev/tcp/$1/22\" >/dev/null 2>&1; then echo answered; else echo no_answer; fi",
    );
    Some(UnderlayProbe {
        tcp_pull: tcp,
        udp_gossip: udp,
        tcp_positive_control: control,
    })
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
        "usage: live_linux_control_surface_exposure_test.sh --ssh-identity-file <path> --client-host <user@host> [options]\n\
         opt-in (OWNER MUST APPROVE the check redefinition): --expected-listener-set [--expect-gossip-scope-table]"
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
