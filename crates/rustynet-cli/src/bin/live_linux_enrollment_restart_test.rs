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

use rustynetd::enrollment_secret_custody::ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV;

use live_lab_support::{
    LINUX_ENROLLMENT_LEDGER_PATH, LINUX_ENROLLMENT_SECRET_PATH, LINUX_MEMBERSHIP_LOG_PATH,
    LINUX_MEMBERSHIP_SNAPSHOT_PATH, LiveLabContext, Logger, MEMBERSHIP_VERIFY_PASS_PREFIX,
    REMOTE_MEMBERSHIP_AUDIT_PATH, REMOTE_RUSTYNET_BIN, RUSTYNET_GOSSIP_PORT, RemoteCliOutcome,
    key_value_field, random_enrollee_pubkey_b64, repo_root, run_cargo_ops,
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

    // AQ-68 (f8be79deb): the minting secret is refused in plaintext unless it
    // was migrated into the OS keystore or the operator opts in. Headless lab
    // guests have no keystore (Secret Service needs a desktop session), and
    // this stage exercises BOTH sides: the CLI's mint and verify, and the
    // admin DAEMON's enrollment IPC, which resolves the same secret on every
    // consume. So the opt-in is scoped two ways: `env` on each CLI call, and
    // a systemd drop-in on the admin daemon for this stage only, removed and
    // verified gone at the end whatever the stage's own result.
    install_lab_custody_opt_in(&ctx, &logger, &admin_host)?;
    let body = run_enrollment_restart_body(
        &ctx,
        &logger,
        &admin_host,
        &enrollee_host,
        &report_path,
        &enrollee_node_id_arg,
    );
    let teardown = remove_lab_custody_opt_in(&ctx, &logger, &admin_host);
    match (body, teardown) {
        (body, Ok(())) => body,
        (Ok(()), Err(teardown)) => Err(format!(
            "the AQ-68 lab opt-in could not be removed, so the admin daemon's fail-closed \
             custody posture is NOT verified restored: {teardown}"
        )),
        (Err(err), Err(teardown)) => Err(format!(
            "{err}; AND the AQ-68 lab opt-in could not be removed: {teardown}"
        )),
    }
}

/// Stages 1-6, run with the stage-scoped AQ-68 opt-in in place.
fn run_enrollment_restart_body(
    ctx: &LiveLabContext,
    logger: &Logger,
    admin_host: &str,
    enrollee_host: &str,
    report_path: &std::path::Path,
    enrollee_node_id_arg: &str,
) -> Result<(), String> {
    let plaintext_opt_in = format!("{ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV}=1");
    let token = ctx
        .rustynet_root_must_succeed(
            admin_host,
            "enrollment mint",
            &[
                "env",
                plaintext_opt_in.as_str(),
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
    let enrollee_addr = LiveLabContext::resolved_target_address(enrollee_host)?;
    let push_addr = format!("{enrollee_addr}:{RUSTYNET_GOSSIP_PORT}");
    logger.line(format!(
        "[enrollment-restart] consuming token on admin for enrollee push_addr={push_addr}"
    ))?;
    let consume = ctx.rustynet_root(
        admin_host,
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
    // With the drop-in installed, a custody refusal from the daemon is
    // impossible by design: the consume reaches the daemon over IPC and the
    // daemon resolves the secret with the opt-in the drop-in exported at its
    // start. If the refusal appears anyway, the drop-in did not take effect
    // and the stage would pass vacuously through the rolled-back arm (the
    // exact vacuous pass a54 §4 flagged). That is a harness/custody defect,
    // so it aborts, like an argv the CLI could not parse.
    if daemon_custody_refusal(&consume) {
        return Err(format!(
            "enrollment consume hit the AQ-68 custody refusal on {admin_host} with the \
             stage-scoped opt-in installed ({LAB_CUSTODY_DROPIN}); the daemon-side \
             opt-in did not take effect, so the stage would pass vacuously"
        ));
    }
    // A consume that got no answer from the daemon (the CLI's transport failure,
    // "daemon unreachable: ...") never reached the enrollment handler, and the
    // SIGKILL below is sent only after the consume has returned. The kill would
    // then interrupt nothing and the stage would pass through the rolled-back
    // arm vacuously, as run linux-u10-aux-enroll-soak-xnet did. The stage
    // cannot judge that, so it aborts.
    if consume_got_no_daemon_answer(&consume) {
        return Err(format!(
            "enrollment consume on {admin_host} got no answer from the daemon, so the \
             kill would interrupt nothing and the stage would pass vacuously: {}",
            consume.detail()
        ));
    }
    // A daemon-side refusal is reported and folded into the outcome checks
    // below, but since a58's correction it can no longer PASS the stage: the
    // harness minted this token seconds ago, so a rejection is a daemon or
    // enrollee defect, and a kill after a nothing-written consume tests no
    // durability (a54 §4:57). An argv the CLI could not parse has already
    // aborted in `rustynet_root`.
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
    let _ = ctx.run_root_allow_failure(admin_host, &["pkill", "-KILL", "rustynetd"]);
    let kill_ms = kill_start.elapsed().as_millis();
    logger.line(format!("[enrollment-restart] kill sent at {kill_ms}ms"))?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    // ── Stage 4: restart admin daemon and wait ────────────────────────────────
    logger.line("[enrollment-restart] restarting admin daemon")?;
    // Clear systemd's failed-start counter before starting: the SIGKILL may
    // have been preceded by failed auto-restarts that armed the unit's start
    // limiter, and the `systemctl start` would then be refused ("Start
    // request repeated too quickly") — the key-custody pattern.
    let _ = ctx.run_root_allow_failure(admin_host, &["systemctl", "reset-failed", "rustynetd"]);
    let _ = ctx.run_root_allow_failure(admin_host, &["systemctl", "start", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(8));

    let admin_recovered = ctx
        .capture_root_allow_failure(admin_host, &["systemctl", "is-active", "rustynetd"])
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
        admin_host,
        "enrollment verify",
        &[
            "env",
            plaintext_opt_in.as_str(),
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
        ctx.rustynet_root(enrollee_host, "status", &[REMOTE_RUSTYNET_BIN, "status"])?;
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
        admin_host,
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

    // a54 §4:57: a stage that never saw the daemon ACCEPT a consume "would
    // pass, vacuously, exercising no enrollment acceptance at all". The
    // rolled-back arm is still reported (outcome_consistent and retryable are
    // checked whatever the consume said), but only an ACCEPTED consume makes
    // the kill meaningful: a rejected consume wrote nothing, so the SIGKILL
    // below tests no durability. The harness mints the token itself seconds
    // earlier, so a daemon-side rejection of a fresh token is a defect or a
    // dead enrollee push target — either way not a pass.
    let overall_pass = admin_recovered
        && membership_integrity == "pass"
        && consume_reported_accepted
        && outcome_consistent
        && retryable_if_rolled_back;

    write_report_and_exit(
        logger,
        report_path,
        if admin_recovered { "pass" } else { "fail" },
        enrollment_outcome,
        membership_integrity,
        &kill_ms.to_string(),
        if overall_pass { "pass" } else { "fail" },
    )?;

    append_standalone_matrix_row(report_path, overall_pass);

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

/// Drop-in that gives the admin daemon the AQ-68 lab opt-in for this stage.
const LAB_CUSTODY_DROPIN_DIR: &str = "/etc/systemd/system/rustynetd.service.d";
const LAB_CUSTODY_DROPIN: &str =
    "/etc/systemd/system/rustynetd.service.d/99-lab-enrollment-restart-custody.conf";
const LAB_CUSTODY_DROPIN_STAGE: &str = "/tmp/rustynet-lab-enrollment-restart-custody.conf";

fn lab_custody_dropin_body() -> String {
    format!("[Service]\nEnvironment={ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV}=1\n")
}

/// The AQ-68 custody refusal, as the daemon's per-consume resolution words it
/// (rustynetd/src/enrollment_secret_custody.rs). The consume CLI only relays
/// IPC; the refusal is produced daemon-side, so its presence in the outcome
/// means the running daemon does not carry the stage-scoped opt-in.
fn daemon_custody_refusal(consume: &RemoteCliOutcome) -> bool {
    const CUSTODY_REFUSAL: &str = "refusing plaintext enrollment secret";
    consume.stdout.contains(CUSTODY_REFUSAL) || consume.stderr.contains(CUSTODY_REFUSAL)
}

/// The CLI's IPC transport failure (`send_command` could not connect, write or
/// read; rustynet-cli main.rs maps that to "daemon unreachable: <err>"): the
/// consume got no answer from the daemon. A daemon-side rejection carries the
/// handler's own message instead.
fn consume_got_no_daemon_answer(consume: &RemoteCliOutcome) -> bool {
    const TRANSPORT_FAILURE: &str = "daemon unreachable:";
    !consume.succeeded()
        && (consume.stdout.contains(TRANSPORT_FAILURE)
            || consume.stderr.contains(TRANSPORT_FAILURE))
}

/// Run a root argv on `host`; a non-zero exit is an error naming `what`.
fn root_ok(ctx: &LiveLabContext, host: &str, args: &[&str], what: &str) -> Result<(), String> {
    let out = ctx.run_root_allow_failure(host, args)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} failed on {host} (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn restart_admin_daemon_and_wait(ctx: &LiveLabContext, host: &str) -> Result<(), String> {
    root_ok(
        ctx,
        host,
        &["systemctl", "daemon-reload"],
        "systemctl daemon-reload",
    )?;
    let _ = ctx.run_root_allow_failure(host, &["systemctl", "reset-failed", "rustynetd"]);
    root_ok(
        ctx,
        host,
        &["systemctl", "restart", "rustynetd"],
        "systemctl restart rustynetd",
    )?;
    wait_for_daemon_ipc(ctx, host)
}

/// Seconds to wait for a restarted daemon to answer IPC.
const DAEMON_IPC_READY_SECS: u32 = 60;

/// Wait until the daemon on `host` answers IPC, not merely until systemd calls
/// the unit active. `systemctl is-active` turns true as soon as the process
/// starts, before the daemon has bound its socket, and a consume sent in that
/// window never reaches the daemon: run linux-u10-aux-enroll-soak-xnet got
/// "daemon unreachable: connect /run/rustynet/rustynetd.sock failed: Connection
/// refused" and then passed through the rolled-back arm. `rustynet status` goes
/// over the same socket the consume uses, so its answer is the readiness signal.
fn wait_for_daemon_ipc(ctx: &LiveLabContext, host: &str) -> Result<(), String> {
    let mut last = String::from("rustynetd never reported active");
    for _ in 0..DAEMON_IPC_READY_SECS {
        let active = ctx
            .capture_root_allow_failure(host, &["systemctl", "is-active", "rustynetd"])
            .map(|s| s.trim() == "active")
            .unwrap_or(false);
        if active {
            let status = ctx.rustynet_root(host, "status", &[REMOTE_RUSTYNET_BIN, "status"])?;
            if status.succeeded() {
                return Ok(());
            }
            last = status.detail();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(format!(
        "rustynetd on {host} did not answer IPC (`rustynet status`) within \
         {DAEMON_IPC_READY_SECS}s; last: {last}"
    ))
}

/// Install the stage-scoped AQ-68 opt-in on the admin daemon (fail closed on a
/// leftover from an earlier run, which would make the posture ambiguous).
fn install_lab_custody_opt_in(
    ctx: &LiveLabContext,
    logger: &Logger,
    admin_host: &str,
) -> Result<(), String> {
    let leftover = ctx.run_root_allow_failure(admin_host, &["test", "-e", LAB_CUSTODY_DROPIN])?;
    if leftover.status.success() {
        return Err(format!(
            "ambiguous leftover: {LAB_CUSTODY_DROPIN} already exists on {admin_host} (an \
             earlier run leaked its AQ-68 opt-in); refusing to run. Once no stage is in \
             flight, remove it by hand on {admin_host}: sudo rm -f {LAB_CUSTODY_DROPIN} \
             && sudo systemctl daemon-reload && sudo systemctl restart rustynetd"
        ));
    }
    let local = std::env::temp_dir().join(format!(
        "rustynet-lab-enrollment-restart-custody-{}.conf",
        std::process::id()
    ));
    std::fs::write(&local, lab_custody_dropin_body())
        .map_err(|err| format!("write local drop-in {}: {err}", local.display()))?;
    let installed = (|| {
        ctx.scp_to(&local, admin_host, LAB_CUSTODY_DROPIN_STAGE)?;
        root_ok(
            ctx,
            admin_host,
            &["mkdir", "-p", LAB_CUSTODY_DROPIN_DIR],
            "mkdir drop-in dir",
        )?;
        root_ok(
            ctx,
            admin_host,
            &[
                "install",
                "-m",
                "0644",
                LAB_CUSTODY_DROPIN_STAGE,
                LAB_CUSTODY_DROPIN,
            ],
            "install drop-in",
        )?;
        let _ = ctx.run_root_allow_failure(admin_host, &["rm", "-f", LAB_CUSTODY_DROPIN_STAGE]);
        restart_admin_daemon_and_wait(ctx, admin_host)
    })();
    let _ = std::fs::remove_file(&local);
    if let Err(err) = installed {
        let teardown = remove_lab_custody_opt_in(ctx, logger, admin_host);
        return Err(format!(
            "{err}; teardown: {}",
            teardown.err().unwrap_or_else(|| "verified".to_owned())
        ));
    }
    logger.line(
        "[enrollment-restart] AQ-68 lab opt-in installed on the admin daemon (this stage only)",
    )?;
    Ok(())
}

/// Remove the opt-in and VERIFY it is gone and the daemon is back, so the
/// admin daemon's fail-closed custody posture is restored.
fn remove_lab_custody_opt_in(
    ctx: &LiveLabContext,
    logger: &Logger,
    admin_host: &str,
) -> Result<(), String> {
    root_ok(
        ctx,
        admin_host,
        &["rm", "-f", LAB_CUSTODY_DROPIN],
        "remove drop-in",
    )?;
    restart_admin_daemon_and_wait(ctx, admin_host)?;
    let still_there =
        ctx.run_root_allow_failure(admin_host, &["test", "-e", LAB_CUSTODY_DROPIN])?;
    if still_there.status.success() {
        return Err(format!(
            "{LAB_CUSTODY_DROPIN} is still present on {admin_host} after removal"
        ));
    }
    logger.line(
        "[enrollment-restart] AQ-68 lab opt-in removed; admin daemon back to fail-closed custody",
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // Review BINSREV F1: the start-limit reset must precede the start in run().
    #[test]
    fn start_resets_start_limit_before_start() {
        let source = include_str!("live_linux_enrollment_restart_test.rs");
        let impl_end = source.find("\n#[cfg(test)]").unwrap_or(source.len());
        let body = &source[..impl_end];
        let reset = body
            .find("\"reset-failed\"")
            .expect("reset-failed must be issued before the start");
        let start = body[reset..]
            .find("\"start\"")
            .expect("a start follows the reset-failed");
        assert!(start > 0, "reset-failed must precede the start");
    }

    // Review a55 (Q3): with the opt-in installed, the daemon-side custody
    // refusal is a harness defect, not a live result — the stage must abort
    // instead of passing vacuously through the rolled-back arm.
    #[test]
    fn custody_refusal_guard_matches_the_daemon_refusal_and_nothing_else() {
        let refusal = RemoteCliOutcome {
            exit_code: 1,
            stdout: "error: refusing plaintext enrollment secret at \
                     /var/lib/rustynet/enrollment-secret"
                .to_owned(),
            stderr: String::new(),
        };
        assert!(daemon_custody_refusal(&refusal));
        let accepted = RemoteCliOutcome {
            exit_code: 0,
            stdout: "enrollment accepted node=enrollee".to_owned(),
            stderr: String::new(),
        };
        assert!(!daemon_custody_refusal(&accepted));
        let other_failure = RemoteCliOutcome {
            exit_code: 1,
            stdout: "error: token rejected: signature mismatch".to_owned(),
            stderr: String::new(),
        };
        assert!(!daemon_custody_refusal(&other_failure));
    }

    #[test]
    fn custody_refusal_guard_runs_before_the_outcome_is_judged() {
        let source = include_str!("live_linux_enrollment_restart_test.rs");
        let impl_end = source.find("\n#[cfg(test)]").unwrap_or(source.len());
        let body = &source[..impl_end];
        let guard = body
            .find("daemon_custody_refusal(&consume)")
            .expect("the custody-refusal guard must be wired after the consume");
        let judged = body
            .find("outcome_consistent = ")
            .expect("the outcome judgement follows the guard");
        assert!(
            guard < judged,
            "the guard must run before the outcome is judged"
        );
    }

    #[test]
    fn dropin_body_is_a_service_environment_line_for_the_custody_var() {
        let body = lab_custody_dropin_body();
        assert!(body.starts_with("[Service]\nEnvironment="));
        assert!(body.ends_with("=1\n"));
        assert!(body.contains(ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV));
    }

    // Run linux-u10-aux-enroll-soak-xnet: the consume never reached the daemon
    // (its socket was not bound yet), and the stage passed through the
    // rolled-back arm. A consume with no daemon answer must abort the stage.
    #[test]
    fn no_answer_guard_matches_the_transport_failure_and_nothing_else() {
        let no_answer = RemoteCliOutcome {
            exit_code: 70,
            stdout: "error [transient_failure (70)]: daemon unreachable: connect \
                     /run/rustynet/rustynetd.sock failed: Connection refused (os error 111)"
                .to_owned(),
            stderr: String::new(),
        };
        assert!(consume_got_no_daemon_answer(&no_answer));
        let on_stderr = RemoteCliOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: "daemon unreachable: read failed: unexpected end of file".to_owned(),
        };
        assert!(consume_got_no_daemon_answer(&on_stderr));
        let accepted = RemoteCliOutcome {
            exit_code: 0,
            stdout: "enrollment accepted node=enrollee".to_owned(),
            stderr: String::new(),
        };
        assert!(!consume_got_no_daemon_answer(&accepted));
        let daemon_rejection = RemoteCliOutcome {
            exit_code: 1,
            stdout: "error: token rejected: signature mismatch".to_owned(),
            stderr: String::new(),
        };
        assert!(!consume_got_no_daemon_answer(&daemon_rejection));
    }

    #[test]
    fn no_answer_guard_runs_before_the_outcome_is_judged() {
        let source = include_str!("live_linux_enrollment_restart_test.rs");
        let impl_end = source.find("\n#[cfg(test)]").unwrap_or(source.len());
        let body = &source[..impl_end];
        let guard = body
            .find("consume_got_no_daemon_answer(&consume)")
            .expect("the no-answer guard must be wired after the consume");
        let judged = body
            .find("let consume_reported_accepted")
            .expect("the consume outcome is judged after the guards");
        assert!(
            guard < judged,
            "the guard must run before the outcome is judged"
        );
    }

    // `systemctl is-active` is true before the daemon binds its socket, so the
    // opt-in restart must also wait for the daemon to answer IPC.
    #[test]
    fn opt_in_restart_waits_for_the_daemon_to_answer_ipc() {
        let source = include_str!("live_linux_enrollment_restart_test.rs");
        let impl_end = source.find("\n#[cfg(test)]").unwrap_or(source.len());
        let body = &source[..impl_end];
        let restart = body
            .find("fn restart_admin_daemon_and_wait(")
            .expect("restart helper exists");
        let restart_body = &body[restart..];
        let restart_end = restart_body.find("\n}\n").unwrap_or(restart_body.len());
        assert!(
            restart_body[..restart_end].contains("wait_for_daemon_ipc(ctx, host)"),
            "the restart helper must end by waiting for IPC, not only is-active"
        );
        let wait = body
            .find("fn wait_for_daemon_ipc(")
            .expect("IPC readiness helper exists");
        let wait_body = &body[wait..];
        let wait_end = wait_body.find("\n}\n").unwrap_or(wait_body.len());
        assert!(
            wait_body[..wait_end].contains("&[REMOTE_RUSTYNET_BIN, \"status\"]"),
            "readiness must be an IPC round trip (`rustynet status`)"
        );
    }

    // a54 §4:57: a consume that was never accepted must not let the stage pass
    // through the rolled-back arm — a kill after a nothing-written consume
    // tests no durability.
    #[test]
    fn overall_pass_requires_the_consume_to_have_been_accepted() {
        let source = include_str!("live_linux_enrollment_restart_test.rs");
        let impl_end = source.find("\n#[cfg(test)]").unwrap_or(source.len());
        let body = &source[..impl_end];
        let overall = body
            .find("let overall_pass = admin_recovered")
            .expect("the overall pass expression exists");
        let overall_body = &body[overall..];
        let overall_end = overall_body.find(';').unwrap_or(overall_body.len());
        let expr = &overall_body[..overall_end];
        for required in [
            "consume_reported_accepted",
            "outcome_consistent",
            "retryable_if_rolled_back",
            "membership_integrity == \"pass\"",
        ] {
            assert!(
                expr.contains(required),
                "overall_pass must require {required}"
            );
        }
    }
}
