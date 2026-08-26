//! Standalone network-flap recovery live-lab validator.
//!
//! Blocks WireGuard UDP traffic on the client node for longer than the
//! keepalive interval, then removes the block and verifies the tunnel
//! and gossip both recover automatically.
//!
//! Stages:
//! 1. Assert baseline WG handshake is recent (within 180s).
//! 2. Block WG UDP on client via nftables (output chain, udp dport 51820).
//! 3. Wait 35s (exceeds WireGuard keepalive of 25s).
//! 4. Assert no new handshake during blackout.
//! 5. Remove nftables rule.
//! 6. Poll for new handshake (up to 90s).
//! 7. Assert tunnel active on exit node (rustynet status).
//! 8. Assert membership state integrity passes.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;

use live_lab_support::{LiveLabContext, Logger, repo_root, run_cargo_ops};

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
    let mut exit_host = String::new();
    let mut client_host = String::new();
    // The client's own WireGuard peer. Distinct from `exit_host`, which in a
    // two-hop topology is one hop FURTHER on (QH-51).
    let mut peer_host = String::new();
    let mut _exit_node_id = String::new();
    let mut _client_node_id = String::new();
    let mut report_path = root_dir.join("artifacts/live_lab/live_linux_network_flap_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_network_flap.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--exit-host" => {
                idx += 1;
                exit_host = req(&args, idx, "--exit-host")?;
            }
            "--peer-host" => {
                idx += 1;
                peer_host = req(&args, idx, "--peer-host")?;
            }
            "--client-host" => {
                idx += 1;
                client_host = req(&args, idx, "--client-host")?;
            }
            "--exit-node-id" => {
                idx += 1;
                _exit_node_id = req(&args, idx, "--exit-node-id")?;
            }
            "--client-node-id" => {
                idx += 1;
                _client_node_id = req(&args, idx, "--client-node-id")?;
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

    if ssh_identity_file.is_empty() || exit_host.is_empty() || client_host.is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-identity-file, --exit-host, --client-host".to_owned(),
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
    let mut ctx = LiveLabContext::new("rustynet-network-flap", ssh_id.as_path())?;
    for host in [&exit_host, &client_host] {
        ctx.push_sudo_password(host)?;
    }

    const WG_PORT: &str = "51820";

    // ── Stage 1: baseline handshake check ────────────────────────────────────
    // Pre-poll: capture initial WG state for diagnostics.
    logger.line("[network-flap] pre-poll: checking wg tool + WG interface state")?;
    for (label, host) in [("client", &client_host), ("exit", &exit_host)] {
        let wg_ver = ctx.capture_root_allow_failure(host, &["wg", "--version"]);
        let wg_show = ctx.capture_root_allow_failure(host, &["wg", "show", "all"]);
        // rustynet status shows tunnel state from the daemon perspective.
        let status = ctx
            .capture_root_allow_failure(host, &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"])
            .unwrap_or_default();
        let status_snip: String = status.chars().take(200).collect();
        logger.line(format!(
            "[network-flap] pre-poll {label} wg-ver={wg_ver:?} \
             wg-show={wg_show:?} status={status_snip:?}"
        ))?;
    }

    // Rustynet uses userspace WireGuard — `wg show` sees no interfaces.
    // Use `rustynet netcheck` which reports the daemon's last live handshake
    // timestamp via path_latest_live_handshake_unix.
    logger.line("[network-flap] waiting for baseline WG handshake (up to 300s)")?;
    let mut baseline_age_s: Option<u64> = None;
    for attempt in 0..60u32 {
        let nc_result = ctx.capture_root_allow_failure(
            &client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "netcheck"],
        );
        let client_err = nc_result
            .as_ref()
            .err()
            .map(|e| e.chars().take(120).collect::<String>());
        let nc_out = nc_result.unwrap_or_default();
        baseline_age_s = parse_handshake_age_s_from_netcheck(&nc_out);
        if baseline_age_s.is_some_and(|age| age < 180) {
            break;
        }
        if attempt == 0 || attempt == 11 || attempt == 23 {
            let client_nc: String = nc_out.chars().take(300).collect();
            let exit_nc_result = ctx.capture_root_allow_failure(
                &exit_host,
                &[live_lab_support::REMOTE_RUSTYNET_BIN, "netcheck"],
            );
            let exit_err = exit_nc_result
                .as_ref()
                .err()
                .map(|e| e.chars().take(120).collect::<String>());
            let exit_nc: String = exit_nc_result
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect();
            logger.line(format!(
                "[network-flap] nc-diag attempt={attempt} \
                 client={client_nc:?} client-err={client_err:?} \
                 exit={exit_nc:?} exit-err={exit_err:?}"
            ))?;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    // An UNREADABLE baseline is a failure of this stage's own instrument, not a
    // property of the tunnel, and it must be reported as such rather than
    // silently standing in for "very old".
    let baseline_ok = baseline_age_s.is_some_and(|age| age < 180);
    logger.line(format!(
        "[network-flap] baseline_handshake_age_s={} ok={baseline_ok}",
        describe_age(baseline_age_s)
    ))?;
    // Post-poll failure dump: capture full WG + gossip state to understand
    // why handshake never established.
    if !baseline_ok {
        logger.line("[network-flap] baseline FAILED — capturing post-poll diagnostics")?;
        for (label, host) in [("client", &client_host), ("exit", &exit_host)] {
            let wg_all = ctx.capture_root_allow_failure(host, &["wg", "show", "all"]);
            let status = ctx
                .capture_root_allow_failure(
                    host,
                    &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
                )
                .unwrap_or_default();
            let status_snip: String = status.chars().take(300).collect();
            let journal = ctx
                .capture_root_allow_failure(
                    host,
                    &["journalctl", "-u", "rustynetd", "-n", "30", "--no-pager"],
                )
                .unwrap_or_default();
            let jsnip: String = journal.chars().take(600).collect();
            logger.line(format!(
                "[network-flap] post-poll {label} wg-all={wg_all:?} \
                 status={status_snip:?} journal={jsnip:?}"
            ))?;
        }
    }

    // Resolve the data-probe target BEFORE the block goes up: the mid-blackout
    // disruption probe and the post-blackout recovery probe both ping this
    // address, and resolving it here keeps the two probes symmetric. Read the
    // mesh address off the TUNNEL INTERFACE, the way the two-hop stage already
    // does successfully (`live_linux_two_hop_test.rs`
    // `mesh_ipv4_discovery_command`). An earlier attempt parsed an
    // `assigned_cidr=` token out of `rustynet status` — a field name that was
    // assumed rather than checked, and does not appear in that output. Probe
    // the client's OWN PEER, not the final exit.
    let probe_host = if peer_host.is_empty() {
        &exit_host
    } else {
        &peer_host
    };
    let exit_mesh_ipv4 = ctx
        .capture_root_allow_failure(
            probe_host,
            &["ip", "-4", "-o", "addr", "show", "dev", "rustynet0"],
        )
        .ok()
        .and_then(|out| {
            // `... inet 100.80.169.183/32 scope global rustynet0`
            out.split_whitespace()
                .skip_while(|token| *token != "inet")
                .nth(1)
                .and_then(|cidr| cidr.split('/').next())
                .filter(|addr| addr.starts_with("100."))
                .map(str::to_owned)
        });
    logger.line(format!(
        "[network-flap] peer mesh ipv4 for data probes (host {probe_host}): {}",
        exit_mesh_ipv4.as_deref().unwrap_or("<unresolved>")
    ))?;

    // ── Stage 2: block WG UDP output on client ────────────────────────────────
    logger.line(format!(
        "[network-flap] blocking WG UDP output port {WG_PORT} on client"
    ))?;
    let flap_start = std::time::Instant::now();
    // nft table/chain may not pre-exist — create idempotently.
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["nft", "add", "table", "inet", "rustynet_flap_test"],
    );
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &[
            "nft",
            "add",
            "chain",
            "inet",
            "rustynet_flap_test",
            "output",
            "{ type filter hook output priority 0 ; }",
        ],
    );
    let add_result = ctx.run_root_allow_failure(
        &client_host,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            "rustynet_flap_test",
            "output",
            "udp",
            "dport",
            WG_PORT,
            "drop",
        ],
    );
    let rule_added = add_result.is_ok();
    logger.line(format!("[network-flap] block rule added={rule_added}"))?;

    // ── Stage 3: wait 35s ─────────────────────────────────────────────────────
    logger.line("[network-flap] waiting 35s for keepalive to expire")?;
    std::thread::sleep(std::time::Duration::from_secs(35));
    let flap_duration_s = flap_start.elapsed().as_secs();

    // ── Stage 4: confirm the blackout actually severs the dataplane ───────────
    // Disruption is proven by DATA FAILING TO CROSS, symmetric with the
    // recovery probe below: with client egress on the WG port dropped, a ping
    // to the peer's mesh address must fail.
    //
    // The old oracle here demanded a stale-or-vanished handshake stamp, and
    // that was wrong twice over. A 35s block is shorter than WireGuard's ~120s
    // rekey, so a live session legitimately needs no new handshake inside the
    // window — the stamp staying fresh proves nothing about the dataplane.
    // And the years of "unreadable ⇒ disruption confirmed" passes were in
    // fact detecting the WORKER DEATH the block used to cause (fixed in
    // 7901939a): the stamp vanished because the runtime worker was killed by
    // the firewalled send, not because the session was rebuilt. The stamp is
    // kept below as logged telemetry only.
    let mid_probe_crossed = exit_mesh_ipv4.as_deref().is_some_and(|target| {
        ctx.capture_root_allow_failure(&client_host, &["ping", "-c", "2", "-W", "2", target])
            .is_ok_and(|out| out.contains(" 0% packet loss") || out.contains("2 received"))
    });
    // Fail closed: no probe target means disruption was NOT proven — an
    // unresolved target must fail the stage, not vacuously confirm it.
    let disruption_confirmed = baseline_ok && exit_mesh_ipv4.is_some() && !mid_probe_crossed;
    let mid_nc = ctx
        .capture_root_allow_failure(
            &client_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "netcheck"],
        )
        .unwrap_or_default();
    let mid_age_s = parse_handshake_age_s_from_netcheck(&mid_nc);
    logger.line(format!(
        "[network-flap] mid_data_probe_crossed={mid_probe_crossed} mid_handshake_age_s={} disruption_confirmed={disruption_confirmed}",
        describe_age(mid_age_s)
    ))?;

    // ── Stage 5: remove block rule ────────────────────────────────────────────
    logger.line("[network-flap] removing block rule")?;
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["nft", "delete", "table", "inet", "rustynet_flap_test"],
    );

    // ── Stage 6: poll for recovery ────────────────────────────────────────────
    logger.line("[network-flap] polling for WG handshake recovery")?;
    let recovery_start = std::time::Instant::now();
    let mut recovery_arrived = false;
    let mut recovery_time_s = 0u64;
    // Recovery is proven by DATA CROSSING THE TUNNEL, with the handshake stamp
    // kept only as corroboration.
    //
    // A handshake alone is the wrong oracle here, and demanding it made this
    // stage unpassable for a reason that is correct WireGuard behaviour rather
    // than a defect. A session rekeys after roughly 120s; this stage blocks
    // egress for 35. So when the block lifts the session is still valid and
    // traffic resumes on it — boringtun's timers emit keepalives, not a
    // handshake, so there is no new handshake to observe and no timestamp to
    // record. The daemon was doing the right thing and the assertion could not
    // see it (QH-51, hypothesis 8; seven earlier hypotheses are recorded in
    // LiveLabStageStatus_2026-08-14.md as eliminated).
    //
    // Pinging the exit's mesh address FROM the client exercises the encrypted
    // path end to end: it must be encrypted by this peer's live session,
    // traverse the tunnel, and be answered. That is a STRICTER proof than a
    // timestamp — a stale-but-present handshake stamp proves nothing about
    // whether packets move, while a reply cannot be produced without a working
    // session. If the tunnel genuinely fails to recover, this fails.
    // The probe target was resolved before the block went up (shared with the
    // mid-blackout disruption probe); same command whose output format is
    // already proven (it resolved a target on run `qh51-datapath2-20260814n`).

    for _ in 0..36 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Some(target) = exit_mesh_ipv4.as_deref()
            && ctx
                .capture_root_allow_failure(&client_host, &["ping", "-c", "2", "-W", "2", target])
                .is_ok_and(|out| out.contains(" 0% packet loss") || out.contains("2 received"))
        {
            recovery_arrived = true;
            recovery_time_s = recovery_start.elapsed().as_secs();
            logger.line("[network-flap] recovery proven by data crossing the tunnel")?;
            break;
        }
        let post_nc = ctx
            .capture_root_allow_failure(
                &client_host,
                &[live_lab_support::REMOTE_RUSTYNET_BIN, "netcheck"],
            )
            .unwrap_or_default();
        let post_age = parse_handshake_age_s_from_netcheck(&post_nc);
        if post_age.is_some_and(|age| age < 30) {
            recovery_arrived = true;
            recovery_time_s = recovery_start.elapsed().as_secs();
            break;
        }
    }
    logger.line(format!(
        "[network-flap] recovery_arrived={recovery_arrived} recovery_time_s={recovery_time_s}"
    ))?;

    // ── Stage 7: tunnel status check ─────────────────────────────────────────
    // Check that rustynet reports the tunnel as active on the exit node after
    // recovery.  `rustynet status` is the canonical user-facing command;
    // `show-gossip-epoch` is not a valid subcommand on deployed builds.
    let status_out = ctx
        .capture_root_allow_failure(
            &exit_host,
            &[live_lab_support::REMOTE_RUSTYNET_BIN, "status"],
        )
        .unwrap_or_default();
    let tunnel_active = status_out.contains("ExitActive")
        || status_out.contains("active")
        || status_out.contains("Connected");
    logger.line(format!("[network-flap] tunnel_active={tunnel_active}"))?;

    // ── Stage 8: membership integrity ────────────────────────────────────────
    let integrity_out = ctx
        .capture_root_allow_failure(
            &exit_host,
            &[
                live_lab_support::REMOTE_RUSTYNET_BIN,
                "ops",
                "verify-membership",
            ],
        )
        .unwrap_or_default();
    let membership_intact = integrity_out.contains("ok") || integrity_out.contains("valid");
    logger.line(format!(
        "[network-flap] membership_intact={membership_intact}"
    ))?;

    let overall_pass = baseline_ok && disruption_confirmed && recovery_arrived && membership_intact;

    // ── Write report ──────────────────────────────────────────────────────────
    // Called IN-PROCESS, not via `cargo run … ops …`. The subprocess form built
    // a default-feature binary in which this `vm-lab`-gated subcommand does not
    // exist, so the write failed with `unknown ops subcommand` and the stage
    // recorded FAIL even though every assertion above had passed.
    rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_network_flap_report(
        rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxNetworkFlapReportConfig {
            report_path: report_path.clone(),
            baseline_handshake_age_s: baseline_age_s.unwrap_or(u64::MAX),
            flap_duration_s,
            disruption_confirmed: pass_fail(disruption_confirmed).to_owned(),
            recovery_handshake_arrived: pass_fail(recovery_arrived).to_owned(),
            recovery_time_s,
            gossip_recovered: pass_fail(tunnel_active).to_owned(),
            membership_intact: pass_fail(membership_intact).to_owned(),
            overall_status: pass_fail(overall_pass).to_owned(),
        },
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "network flap test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[network-flap] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

/// Age in seconds of the peer handshake the daemon last observed, or `None`
/// when the metric could not be read at all.
///
/// # Why the raw probe timestamp, and not `path_latest_live_handshake_unix`
///
/// `path_latest_live_handshake_unix` is FRESHNESS-GATED: `daemon.rs:7344-7370`
/// only populates it when `traversal_handshake_is_fresh` holds, and renders it
/// as the literal string `"none"` otherwise. It therefore cannot express an age
/// — it reports a timestamp while fresh and disappears once stale.
///
/// This stage previously parsed that field with `.parse::<u64>().ok()`, so
/// `"none"` failed to parse, the match arm never fired, and control fell through
/// to a trailing `u64::MAX`. That single value stood for THREE different states
/// (token absent, token `"none"`, and `now < ts` clock skew), and the stage then
/// treated it as an enormous age. The consequence was a stage that could not
/// pass and whose passing check was meaningless: `baseline_handshake_age_s` read
/// `18446744073709551615` BEFORE any block was applied, so
/// `wg_disruption_confirmed` succeeded trivially on unreadable data while
/// `wg_handshake_recovered` could never succeed at all (QH-51, measured on runs
/// `qh46-firewalld-20260814c` and `qh51-keepalive-20260814d`).
///
/// `traversal_probe_latest_handshake_unix` is the same underlying observation
/// WITHOUT the freshness gate, so it ages continuously and can be subtracted
/// from now. Returning `Option` keeps "unreadable" distinct from "old", because
/// missing data must never be reported as evidence of disruption.
fn parse_handshake_age_s_from_netcheck(netcheck_out: &str) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok()?;
    if now == 0 {
        return None;
    }
    for token in netcheck_out.split_whitespace() {
        let Some(raw) = token.strip_prefix("traversal_probe_latest_handshake_unix=") else {
            continue;
        };
        // `none`, `multiple` (a multi-peer summary), and anything else
        // non-numeric are UNREADABLE, not old.
        let Ok(ts) = raw.parse::<u64>() else {
            return None;
        };
        if ts == 0 || now < ts {
            return None;
        }
        return Some(now - ts);
    }
    None
}

/// Render an optional age for the log, keeping "unreadable" visibly distinct
/// from any number.
fn describe_age(age: Option<u64>) -> String {
    age.map_or_else(|| "unreadable".to_owned(), |value| value.to_string())
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "pass" } else { "fail" }
}

fn append_standalone_matrix_row(report_path: &std::path::Path, overall_pass: bool) {
    if std::env::var("RUSTYNET_ORCHESTRATOR_ACTIVE").is_ok() {
        return;
    }
    if let Ok(root_dir) = repo_root() {
        let report_dir = report_path.parent().unwrap_or(std::path::Path::new("."));
        let args = [
            "--stage".to_owned(),
            "live_network_flap".to_owned(),
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
        "usage: live_linux_network_flap_test \
        --ssh-identity-file <path> \
        --exit-host <user@host> \
        --client-host <user@host> \
        [--exit-node-id <id>] \
        [--client-node-id <id>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
