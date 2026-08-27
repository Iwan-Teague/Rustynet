//! Standalone enrollment-under-kill consistency live-lab validator.
//!
//! Tests that the daemon keeps consistent enrollment state when killed after an
//! enrollment. Either the token was consumed and the on-disk ledger says so, or
//! it was not consumed and is still valid to retry — no partial state.
//!
//! Stages:
//! 1. Mint an enrollment token on the admin node (`rustynet enrollment mint`).
//! 2. Consume it on the admin node (`rustynet enrollment consume`, IPC to the
//!    local daemon), presenting the enrollee's pubkey and gossip push address.
//! 3. Kill rustynetd on the admin node with SIGKILL.
//! 4. Restart the admin daemon and wait for recovery.
//! 5. Read the consumed-token ledger back with `rustynet enrollment verify` and
//!    require it to agree with what the consume reported, and require an
//!    unconsumed token to still be valid (retryable).
//! 6. Verify membership log integrity on the admin (`rustynet membership
//!    verify`).
//!
//! Every remote `rustynet` call goes through `LiveLabContext::rustynet_root`,
//! which FAILS THE STAGE when the CLI cannot parse the argv. That is deliberate
//! (HARNESS-VERBS): this stage previously drove four `ops` subcommands that the
//! parser has never had — `generate-enrollment-token`,
//! `consume-enrollment-token`, `show-node-id` and `verify-membership` — through
//! allow-failure helpers that keep stdout only. Because the CLI prints its
//! errors to stdout, each failure looked like data: the mint took a "no anchor
//! state?" graceful skip and the other three degraded into
//! `enrollment_outcome=rolled_back` with an empty peer list. The stage reported
//! a plausible result while exercising nothing.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;

use live_lab_support::{
    LINUX_ENROLLMENT_LEDGER_PATH, LINUX_ENROLLMENT_SECRET_PATH, LINUX_MEMBERSHIP_LOG_PATH,
    LINUX_MEMBERSHIP_SNAPSHOT_PATH, LiveLabContext, Logger, MEMBERSHIP_VERIFY_PASS_PREFIX,
    REMOTE_MEMBERSHIP_AUDIT_PATH, REMOTE_RUSTYNET_BIN, RUSTYNET_GOSSIP_PORT, key_value_field,
    random_enrollee_pubkey_b64, repo_root, run_cargo_ops,
};

fn main() {
    if let Err(err) = run() {
        let code = classify_error(err.as_str());
        eprintln!("error [{code}]: {err}");
        std::process::exit(code.as_i32());
    }
}

fn classify_error(msg: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = msg.to_ascii_lowercase();
    if lower.contains("missing required") || lower.contains("unknown command") {
        ExitCode::BadArgs
    } else if lower.contains("ssh")
        || lower.contains("timed out")
        || lower.contains("connection refused")
    {
        ExitCode::TransientFailure
    } else if lower.contains("identity file") || lower.contains("config") {
        ExitCode::ConfigError
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let root_dir = repo_root()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut ssh_identity_file = String::new();
    let mut admin_host = String::new();
    let mut enrollee_host = String::new();
    let mut _admin_node_id = String::new();
    let mut enrollee_node_id_arg = String::new();
    let mut report_path =
        root_dir.join("artifacts/live_lab/live_linux_enrollment_restart_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_enrollment_restart.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--admin-host" => {
                idx += 1;
                admin_host = req(&args, idx, "--admin-host")?;
            }
            "--enrollee-host" => {
                idx += 1;
                enrollee_host = req(&args, idx, "--enrollee-host")?;
            }
            "--admin-node-id" => {
                idx += 1;
                _admin_node_id = req(&args, idx, "--admin-node-id")?;
            }
            "--enrollee-node-id" => {
                idx += 1;
                enrollee_node_id_arg = req(&args, idx, "--enrollee-node-id")?;
            }
            "--report-path" => {
                idx += 1;
                report_path = PathBuf::from(req(&args, idx, "--report-path")?);
            }
            "--log-path" => {
                idx += 1;
                log_path = PathBuf::from(req(&args, idx, "--log-path")?);
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

    if ssh_identity_file.is_empty() || admin_host.is_empty() || enrollee_host.is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-identity-file, --admin-host, --enrollee-host"
                .to_owned(),
        );
    }

    for path in [report_path.parent(), log_path.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }

    let logger = Logger::new(&log_path)?;
    let ssh_id = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-enrollment-restart", ssh_id.as_path())?;
    for host in [&admin_host, &enrollee_host] {
        ctx.push_sudo_password(host)?;
    }

    // ── Stage 1: mint enrollment token on admin ───────────────────────────────
    logger.line("[enrollment-restart] minting enrollment token on admin node")?;
    // The enrollment secret is seeded on admin nodes ONLY, deliberately, so the
    // daemon's enrollment IPC stays fail-closed everywhere else. Its absence is
    // therefore the one genuinely-expected failure here, and the only condition
    // that may skip the stage. It is probed for explicitly rather than inferred
    // from a failed mint: this stage used to read ANY mint failure as
    // "no anchor state?" and return a green skip, which is how a call to a verb
    // the parser has never had (`ops generate-enrollment-token --ttl-seconds`)
    // stayed invisible (HARNESS-VERBS).
    let secret_present = ctx
        .run_root_allow_failure(&admin_host, &["test", "-s", LINUX_ENROLLMENT_SECRET_PATH])
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !secret_present {
        logger.line(format!(
            "[enrollment-restart] no enrollment secret at {LINUX_ENROLLMENT_SECRET_PATH} on \
             {admin_host}: this node carries no anchor state — skipping"
        ))?;
        write_report_and_exit(
            &logger,
            &report_path,
            "skipped",
            "skipped",
            "skipped",
            // The report writer parses this as a u64. The previous skip path
            // passed "skipped" here, which made the skip itself return an error.
            "0",
            "skipped",
        )?;
        append_standalone_matrix_row(&report_path, true);
        return Ok(());
    }

    let token = ctx
        .rustynet_root_must_succeed(
            &admin_host,
            "enrollment mint",
            &[
                REMOTE_RUSTYNET_BIN,
                "enrollment",
                "mint",
                "--secret",
                LINUX_ENROLLMENT_SECRET_PATH,
                "--ttl",
                "300",
            ],
        )?
        .trim()
        .to_owned();
    // `enrollment mint` prints the token ALONE on success, precisely so it can be
    // captured cleanly. Anything carrying whitespace is prose, not a token — the
    // exact shape that flowed onward as a "token" when the CLI printed its error
    // to stdout and the caller kept only stdout.
    if token.is_empty() || token.split_whitespace().count() != 1 {
        return Err(format!(
            "enrollment mint did not return a bare token on {admin_host}: {token:?}"
        ));
    }
    logger.line(format!(
        "[enrollment-restart] token minted (len={})",
        token.len()
    ))?;

    // ── Stage 2: consume the token ────────────────────────────────────────────
    // `rustynet enrollment consume` reaches the LOCAL daemon over IPC
    // (`IpcCommand::EnrollmentConsume`), and the handler needs the enrollment
    // secret — which only admin nodes carry. So the consume runs on the admin,
    // presenting the enrollee's key material. That is also what the architecture
    // intends: the node holding the secret validates the token and registers the
    // enrollee as a gossip peer.
    //
    // The verb requires --token AND --pubkey AND --push-addr. The dead
    // `ops consume-enrollment-token --token <t>` it replaces named neither of
    // the last two, and its failure degraded silently into
    // `enrollment_outcome=rolled_back`.
    let enrollee_pubkey_b64 = random_enrollee_pubkey_b64()?;
    let enrollee_addr = LiveLabContext::resolved_target_address(&enrollee_host)?;
    let push_addr = format!("{enrollee_addr}:{RUSTYNET_GOSSIP_PORT}");
    logger.line(format!(
        "[enrollment-restart] consuming token on admin for enrollee push_addr={push_addr}"
    ))?;
    let consume = ctx.rustynet_root(
        &admin_host,
        "enrollment consume",
        &[
            REMOTE_RUSTYNET_BIN,
            "enrollment",
            "consume",
            "--token",
            token.as_str(),
            "--pubkey",
            enrollee_pubkey_b64.as_str(),
            "--push-addr",
            push_addr.as_str(),
        ],
    )?;
    // A refusal here is a legitimate live result — the token may be rejected, the
    // daemon may be unreachable — and the point of the stage is what the state
    // looks like afterwards. Only an argv the CLI could not parse aborts, and
    // `rustynet_root` has already done that.
    let consume_reported_accepted = consume.succeeded()
        && consume
            .trimmed_stdout()
            .contains("enrollment accepted node=");
    logger.line(format!(
        "[enrollment-restart] consume: {}",
        consume.detail()
    ))?;

    // ── Stage 3: SIGKILL admin daemon ─────────────────────────────────────────
    let kill_start = std::time::Instant::now();
    logger.line("[enrollment-restart] sending SIGKILL to rustynetd on admin")?;
    let _ = ctx.run_root_allow_failure(&admin_host, &["pkill", "-KILL", "rustynetd"]);
    let kill_ms = kill_start.elapsed().as_millis();
    logger.line(format!("[enrollment-restart] kill sent at {kill_ms}ms"))?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    // ── Stage 4: restart admin daemon and wait ────────────────────────────────
    logger.line("[enrollment-restart] restarting admin daemon")?;
    let _ = ctx.run_root_allow_failure(&admin_host, &["systemctl", "start", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(8));

    let admin_recovered = ctx
        .capture_root_allow_failure(&admin_host, &["systemctl", "is-active", "rustynetd"])
        .map(|s| s.trim() == "active")
        .unwrap_or(false);
    logger.line(format!(
        "[enrollment-restart] admin daemon recovered={admin_recovered}"
    ))?;

    // ── Stage 5: determine the enrollment outcome from the ledger ─────────────
    // The authoritative post-restart oracle is the consumed-token ledger, read
    // back with `rustynet enrollment verify`: it is on disk, so it survives the
    // SIGKILL, and it states outright whether THIS token was consumed. That
    // replaces two calls that never parsed — `ops show-node-id` and a two-token
    // `peer list` (the CLI has single-token `peers` / `peer-list`) — whose
    // failures both degraded into `enrollment_outcome=rolled_back` with an empty
    // peer list, a plausible-looking answer that proved nothing.
    let verify_out = ctx.rustynet_root_must_succeed(
        &admin_host,
        "enrollment verify",
        &[
            REMOTE_RUSTYNET_BIN,
            "enrollment",
            "verify",
            "--secret",
            LINUX_ENROLLMENT_SECRET_PATH,
            "--token",
            token.as_str(),
            "--ledger",
            LINUX_ENROLLMENT_LEDGER_PATH,
        ],
    )?;
    let verify_line = verify_out.trim();
    let already_consumed = key_value_field(verify_line, "already_consumed").ok_or_else(|| {
        format!("enrollment verify output has no already_consumed field: {verify_line:?}")
    })?;
    let token_still_valid = key_value_field(verify_line, "valid")
        .ok_or_else(|| format!("enrollment verify output has no valid field: {verify_line:?}"))?;
    let ledger_says_consumed = already_consumed == "true";
    logger.line(format!(
        "[enrollment-restart] post-restart ledger: valid={token_still_valid} \
         already_consumed={already_consumed}"
    ))?;

    // Evidence: the enrollee's own node id. There is no `ops show-node-id`; the
    // real surface for a live node's id is the `node_id=` field of the
    // `rustynet status` line the daemon serves over IPC.
    let enrollee_status =
        ctx.rustynet_root(&enrollee_host, "status", &[REMOTE_RUSTYNET_BIN, "status"])?;
    match key_value_field(enrollee_status.trimmed_stdout(), "node_id") {
        Some(observed) => {
            logger.line(format!("[enrollment-restart] enrollee node_id={observed}"))?;
            if !enrollee_node_id_arg.is_empty() && enrollee_node_id_arg != observed {
                logger.line(format!(
                    "[enrollment-restart] NOTE: --enrollee-node-id was {enrollee_node_id_arg:?} \
                     but the enrollee daemon reports {observed:?}"
                ))?;
            }
        }
        None => logger.line(format!(
            "[enrollment-restart] enrollee node_id unavailable: {}",
            enrollee_status.detail()
        ))?,
    }

    // The property this stage exists to test: NO PARTIAL STATE. Whatever the
    // consume reported before the daemon was killed must still be what the
    // ledger says after it came back...
    let outcome_consistent = consume_reported_accepted == ledger_says_consumed;
    // ...and a token that was NOT consumed must still be retryable, not stranded.
    let retryable_if_rolled_back = ledger_says_consumed || token_still_valid == "true";
    let enrollment_outcome = if ledger_says_consumed {
        "consumed"
    } else {
        "rolled_back"
    };
    logger.line(format!(
        "[enrollment-restart] enrollment_outcome={enrollment_outcome} \
         consume_reported_accepted={consume_reported_accepted} \
         outcome_consistent={outcome_consistent} \
         retryable_if_rolled_back={retryable_if_rolled_back}"
    ))?;

    // ── Stage 6: membership integrity check ───────────────────────────────────
    // `rustynet membership verify`, not the never-existent
    // `ops verify-membership`. `--audit-output` is pinned because the verb's own
    // default is CWD-relative and an SSH command's CWD is the login user's home.
    let integrity = ctx.rustynet_root(
        &admin_host,
        "membership verify",
        &[
            REMOTE_RUSTYNET_BIN,
            "membership",
            "verify",
            "--snapshot",
            LINUX_MEMBERSHIP_SNAPSHOT_PATH,
            "--log",
            LINUX_MEMBERSHIP_LOG_PATH,
            "--audit-output",
            REMOTE_MEMBERSHIP_AUDIT_PATH,
        ],
    )?;
    // Matched against the verb's real success line. The previous
    // `contains("ok") || contains("valid")` heuristic matched neither that line
    // nor any of its failure strings.
    let membership_integrity = if integrity.succeeded()
        && integrity
            .trimmed_stdout()
            .starts_with(MEMBERSHIP_VERIFY_PASS_PREFIX)
    {
        "pass"
    } else {
        "fail"
    };
    logger.line(format!(
        "[enrollment-restart] membership_integrity={membership_integrity} ({})",
        integrity.detail()
    ))?;

    let overall_pass = admin_recovered
        && membership_integrity == "pass"
        && outcome_consistent
        && retryable_if_rolled_back;

    write_report_and_exit(
        &logger,
        &report_path,
        if admin_recovered { "pass" } else { "fail" },
        enrollment_outcome,
        membership_integrity,
        &kill_ms.to_string(),
        if overall_pass { "pass" } else { "fail" },
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "enrollment restart test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[enrollment-restart] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_report_and_exit(
    logger: &Logger,
    report_path: &std::path::Path,
    admin_recovered: &str,
    enrollment_outcome: &str,
    membership_integrity: &str,
    kill_timing_ms: &str,
    overall_status: &str,
) -> Result<(), String> {
    // In-process, not `cargo run … ops …`: the subprocess built a
    // default-feature binary lacking this `vm-lab`-gated verb, so the write
    // failed with `unknown ops subcommand` and the stage recorded FAIL after
    // its assertions had already passed. Parsing `kill_timing_ms` here rather
    // than handing the CLI a string surfaces a malformed value at the call
    // site instead of as an opaque bad_args exit from a child process.
    let status =
        rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_enrollment_restart_report(
            rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxEnrollmentRestartReportConfig {
                report_path: report_path.to_path_buf(),
                admin_recovered: admin_recovered.to_owned(),
                enrollment_outcome: enrollment_outcome.to_owned(),
                membership_integrity: membership_integrity.to_owned(),
                kill_timing_ms: kill_timing_ms.parse::<u64>().map_err(|err| {
                    format!("invalid kill_timing_ms {kill_timing_ms:?}: {err}")
                })?,
                overall_status: overall_status.to_owned(),
            },
        )?;
    logger.line(format!(
        "[enrollment-restart] report written status={status}"
    ))?;
    Ok(())
}

fn append_standalone_matrix_row(report_path: &std::path::Path, overall_pass: bool) {
    if std::env::var("RUSTYNET_ORCHESTRATOR_ACTIVE").is_ok() {
        return;
    }
    if let Ok(root_dir) = repo_root() {
        let report_dir = report_path.parent().unwrap_or(std::path::Path::new("."));
        let args = [
            "--stage".to_owned(),
            "live_enrollment_restart".to_owned(),
            "--status".to_owned(),
            if overall_pass { "pass" } else { "fail" }.to_owned(),
            "--report-path".to_owned(),
            report_path.to_string_lossy().to_string(),
            "--report-dir".to_owned(),
            report_dir.to_string_lossy().to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = run_cargo_ops(&root_dir, "append-live-lab-matrix-row", &refs);
    }
}

fn req(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|v| !v.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_enrollment_restart_test \
        --ssh-identity-file <path> \
        --admin-host <user@host> \
        --enrollee-host <user@host> \
        [--admin-node-id <id>] \
        [--enrollee-node-id <id>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
