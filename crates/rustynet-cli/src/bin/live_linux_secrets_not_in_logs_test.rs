//! Standalone secrets-not-in-logs live-lab validator.
//!
//! Asserts that rustynetd never logs raw key material (WireGuard private keys,
//! ed25519 signing keys, enrollment secrets) to journald.
//!
//! Stages:
//! 1. Flush recent journal entries to establish a baseline.
//! 2. Trigger an enrollment token flow (mint + consume attempt).
//! 3. Collect the last N lines from journalctl -u rustynetd.
//! 4. Scan for 64-char hex strings (WireGuard 256-bit private key pattern).
//! 5. Scan for 32-byte hex strings (ed25519 signing key pattern).
//! 6. Scan for base64 blobs that decode to DER EC key headers.
//! 7. Assert no matches found.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;

use live_lab_support::{
    LiveLabContext, LiveLabPlatform, Logger, MACOS_UNIFIED_LOG_WINDOW, REMOTE_RUSTYNET_BIN,
    daemon_unit_log_argv, enrollment_secret_path, repo_root, run_cargo_ops,
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
    let mut target_host = String::new();
    let mut platform = LiveLabPlatform::Linux;
    let mut report_path =
        root_dir.join("artifacts/live_lab/live_linux_secrets_not_in_logs_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_secrets_not_in_logs.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--target-host" => {
                idx += 1;
                target_host = req(&args, idx, "--target-host")?;
            }
            "--platform" => {
                idx += 1;
                platform = LiveLabPlatform::parse(req(&args, idx, "--platform")?.as_str())?;
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

    if ssh_identity_file.is_empty() || target_host.is_empty() {
        print_usage();
        return Err("missing required argument: --ssh-identity-file, --target-host".to_owned());
    }

    for path in [report_path.parent(), log_path.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }

    let logger = Logger::new(&log_path)?;
    let ssh_id = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-secrets-not-in-logs", ssh_id.as_path())?;
    ctx.push_sudo_password(&target_host)?;

    // The enrollment-secret path the deployed daemon on THIS target was seeded
    // with (launchd passes `${STATE_ROOT}/keys/enrollment.secret` on macOS).
    // Windows fails closed before anything runs.
    let secret_path = enrollment_secret_path(platform)?;

    // ── Stage 1: flush journal cursor ────────────────────────────────────────
    match platform {
        LiveLabPlatform::Linux => {
            logger.line("[secrets-log] flushing journal cursor on target")?;
            let _ = ctx.run_root_allow_failure(&target_host, &["journalctl", "--flush"]);
        }
        _ => {
            logger.line(format!(
                "[secrets-log] skipping journald flush (linux-only; target platform is {})",
                platform.as_str()
            ))?;
        }
    }

    // ── Stage 2: trigger enrollment activity to exercise key paths ────────────
    // The real verb is `rustynet enrollment mint --secret <path> --ttl <secs>`.
    // This stage used to call `rustynet ops generate-enrollment-token
    // --ttl-seconds 60`, which the parser has never had — and it went through an
    // allow-failure helper that keeps stdout only, so the CLI's own error text
    // came back looking like output and the enrollment code path was never
    // exercised at all (HARNESS-VERBS). It also spelled the binary as a bare
    // `rustynet`, which dies as `command not found` under sudo on the RHEL
    // family (QH-61).
    //
    // The one legitimate reason the mint cannot run is that this node has no
    // enrollment secret: it is seeded on admin nodes only, deliberately, so the
    // daemon's enrollment IPC stays fail-closed elsewhere. That is detectable,
    // so it is probed for explicitly and logged. Anything else — an argv the CLI
    // cannot parse, or a mint that fails with the secret present — aborts.
    //
    // Since AQ-68 (f8be79deb) the CLI refuses a plaintext enrollment secret
    // unless it has been migrated into the OS keystore or the operator opts in
    // with RUSTYNET_ALLOW_PLAINTEXT_ENROLLMENT_SECRET. Headless lab guests have
    // no keystore to migrate into (on Linux the store is Secret Service, which
    // needs a desktop session), so this lab mint opts in explicitly, through
    // `env` on this one command only: nothing on the guest is reconfigured and
    // the daemon's own custody posture is untouched.
    logger.line("[secrets-log] triggering enrollment token activity")?;
    let secret_present = ctx
        .run_root_allow_failure(&target_host, &["test", "-s", secret_path])
        .map(|out| out.status.success())
        .unwrap_or(false);
    if secret_present {
        let plaintext_opt_in = format!(
            "{}=1",
            rustynetd::enrollment_secret_custody::ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV
        );
        let minted = ctx.rustynet_root_must_succeed(
            &target_host,
            "enrollment mint",
            &[
                "env",
                plaintext_opt_in.as_str(),
                REMOTE_RUSTYNET_BIN,
                "enrollment",
                "mint",
                "--secret",
                secret_path,
                "--ttl",
                "60",
            ],
        )?;
        // Never log the token itself — this is the secrets-hygiene stage.
        logger.line(format!(
            "[secrets-log] enrollment mint exercised (token len={})",
            minted.trim().len()
        ))?;
    } else {
        logger.line(format!(
            "[secrets-log] no enrollment secret at {secret_path} on \
             {target_host} (non-admin node); the enrollment code path is NOT exercised by \
             this run"
        ))?;
    }
    std::thread::sleep(std::time::Duration::from_secs(3));

    // ── Stage 3: collect daemon log lines ────────────────────────────────────
    // Linux: the journald unit log (unchanged argv). macOS: the unified-log
    // window for the daemon process (FIXED `--last 15m` window, see
    // MACOS_UNIFIED_LOG_WINDOW — never derived from `lines`) PLUS the launchd
    // StandardOut/StandardError files — a plain Rust daemon does not mirror
    // its stderr into the unified log, so the files are where a leak would
    // actually appear. Every chunk is allow-failure (a missing log file is
    // not a custody violation) and every chunk's lines are scanned identically
    // below. D1 (review macos-harness-b): a pass is IMPOSSIBLE when every
    // chunk came back empty — the run fails below with the per-chunk counts
    // instead of reporting a clean scan that read nothing.
    logger.line(format!(
        "[secrets-log] collecting daemon log lines from rustynetd (platform {}; unified-log \
         window fixed at {MACOS_UNIFIED_LOG_WINDOW} on macos; tail chunks honour the lines \
         argument)",
        platform.as_str()
    ))?;
    let log_chunks = daemon_unit_log_argv(platform, "500", true)?;
    let mut journal = String::new();
    let mut chunk_line_counts: Vec<usize> = Vec::with_capacity(log_chunks.len());
    for chunk in &log_chunks {
        let chunk_output = ctx
            .capture_root_allow_failure(&target_host, chunk)
            .unwrap_or_default();
        let chunk_lines = chunk_output.lines().count();
        chunk_line_counts.push(chunk_lines);
        journal.push_str(&chunk_output);
        if !journal.ends_with('\n') {
            journal.push('\n');
        }
    }

    // Count what was ACTUALLY collected (sum of the chunks' own line counts),
    // not the newline-padded merge buffer: padding an empty collection to
    // "\n" must not read as one scanned line.
    let line_count: usize = chunk_line_counts.iter().sum();
    logger.line(format!(
        "[secrets-log] collected {line_count} journal lines (per chunk: {chunk_line_counts:?})"
    ))?;
    if let Some(refusal) = secrets_zero_line_refusal(&platform, &chunk_line_counts) {
        logger.line(format!("[secrets-log] FAIL {refusal}"))?;
        return Err(refusal);
    }

    // ── Stage 4-6: scan for key patterns ─────────────────────────────────────
    let hex64_matches = scan_hex_pattern(&journal, 64);
    let hex32_matches = scan_hex_pattern(&journal, 32);
    let b64_key_matches = scan_b64_ec_key_headers(&journal);

    let total_suspicious = hex64_matches.len() + hex32_matches.len() + b64_key_matches.len();

    for line in &hex64_matches {
        logger.line(format!(
            "[secrets-log] WARN 64-char hex found: {}",
            redact_line(line)
        ))?;
    }
    for line in &hex32_matches {
        logger.line(format!(
            "[secrets-log] WARN 32-byte hex found: {}",
            redact_line(line)
        ))?;
    }
    for line in &b64_key_matches {
        logger.line(format!(
            "[secrets-log] WARN base64 key pattern found: {}",
            redact_line(line)
        ))?;
    }

    let overall_pass = total_suspicious == 0;
    logger.line(format!(
        "[secrets-log] suspicious_matches={total_suspicious} verdict={}",
        if overall_pass { "clean" } else { "FAIL" }
    ))?;

    // ── Write report ──────────────────────────────────────────────────────────
    // In-process, not `cargo run … ops …`: the subprocess built a
    // default-feature binary lacking this `vm-lab`-gated verb, so the write
    // failed with `unknown ops subcommand` and the stage recorded FAIL after
    // its assertions had already passed.
    rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_secrets_not_in_logs_report(
        rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxSecretsNotInLogsReportConfig {
            report_path: report_path.clone(),
            log_lines_checked: line_count as u64,
            suspicious_matches: total_suspicious as u64,
            hex64_matches: hex64_matches.len() as u64,
            hex32_matches: hex32_matches.len() as u64,
            b64_key_matches: b64_key_matches.len() as u64,
            verdict: if overall_pass { "clean" } else { "contaminated" }.to_owned(),
            overall_status: pass_fail(overall_pass).to_owned(),
        },
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "secrets-not-in-logs test failed ({total_suspicious} suspicious matches); see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[secrets-log] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

/// D1 (review macos-harness-b): the named refusal when a secrets scan read
/// nothing. `chunk_line_counts` holds one entry per
/// [`daemon_unit_log_argv`] chunk, in collection order. `Some` ⇒ the caller
/// must fail the run: `total_suspicious == 0` over zero scanned lines is a
/// collection failure, not a clean log, and a pass on it would be
/// indistinguishable from `sudo -n log show` failing or both launchd log
/// files being absent on a fresh/rotated guest.
fn secrets_zero_line_refusal(
    platform: &LiveLabPlatform,
    chunk_line_counts: &[usize],
) -> Option<String> {
    if chunk_line_counts.iter().sum::<usize>() > 0 {
        return None;
    }
    let per_chunk = chunk_line_counts
        .iter()
        .enumerate()
        .map(|(idx, count)| format!("chunk {idx} collected {count} lines"))
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "secrets-not-in-logs log collection read NOTHING on platform {}: {per_chunk} — a pass \
         is impossible without scanned evidence (fail closed; D1)",
        platform.as_str()
    ))
}

fn scan_hex_pattern(text: &str, char_len: usize) -> Vec<String> {
    let mut hits = Vec::new();
    for line in text.lines() {
        // journalctl inserts "-- Boot <boot-id> --" separator lines between boots;
        // the boot-id is not a secret — skip these metadata lines.
        if line.starts_with("-- Boot ") || line.starts_with("-- Reboot ") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i + char_len <= bytes.len() {
            let window = &bytes[i..i + char_len];
            if window.iter().all(|b| b.is_ascii_hexdigit()) {
                // Confirm it's surrounded by non-hex to avoid partial matches inside longer tokens.
                let before_ok = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
                let after_ok =
                    i + char_len == bytes.len() || !bytes[i + char_len].is_ascii_hexdigit();
                if before_ok && after_ok {
                    hits.push(line.to_owned());
                    break;
                }
            }
            i += 1;
        }
    }
    hits
}

fn scan_b64_ec_key_headers(text: &str) -> Vec<String> {
    // Base64-encoded DER headers for EC/Ed25519 private keys start with specific
    // byte patterns that encode to recognizable base64 prefixes.
    // MC4CAQAwBQ... is common for PKCS#8 ed25519. MHQ... for SEC1 EC.
    const B64_KEY_PREFIXES: &[&str] = &["MC4CAQAwBQ", "MHQCAQEEI", "MIGHAgEA"];
    let mut hits = Vec::new();
    for line in text.lines() {
        for prefix in B64_KEY_PREFIXES {
            if line.contains(prefix) {
                hits.push(line.to_owned());
                break;
            }
        }
    }
    hits
}

fn redact_line(line: &str) -> String {
    if line.len() > 80 {
        format!("{}...<redacted>", &line[..40])
    } else {
        "<redacted>".to_owned()
    }
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
            "live_secrets_not_in_logs".to_owned(),
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
        "usage: live_linux_secrets_not_in_logs_test \
        --ssh-identity-file <path> \
        --target-host <user@host> \
        [--platform <linux|macos|windows>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_platform_is_linux_and_argv_stays_byte_identical() {
        // The orchestrator's pre-port invocation passed no --platform; every
        // resolved value must match the historical Linux literals.
        let secret = enrollment_secret_path(LiveLabPlatform::Linux).expect("linux");
        assert_eq!(secret, "/var/lib/rustynet/keys/enrollment.secret");
        let chunks = daemon_unit_log_argv(LiveLabPlatform::Linux, "500", true).expect("linux");
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0],
            vec![
                "journalctl",
                "-u",
                "rustynetd",
                "-n",
                "500",
                "--no-pager",
                "--output=short-monotonic",
            ]
        );
    }

    #[test]
    fn macos_platform_resolves_the_launchd_seed_paths_and_log_sources() {
        let secret = enrollment_secret_path(LiveLabPlatform::MacOs).expect("macos");
        assert_eq!(secret, "/usr/local/var/rustynet/keys/enrollment.secret");
        let chunks = daemon_unit_log_argv(LiveLabPlatform::MacOs, "500", true).expect("macos");
        assert!(chunks.iter().all(|chunk| !chunk.is_empty()));
    }

    #[test]
    fn windows_platform_fails_closed_before_any_remote_work() {
        assert!(enrollment_secret_path(LiveLabPlatform::Windows).is_err());
        assert!(daemon_unit_log_argv(LiveLabPlatform::Windows, "500", true).is_err());
    }

    #[test]
    fn zero_collected_lines_refuse_a_pass_with_platform_and_per_chunk_counts() {
        // D1: a secrets scan that read nothing must fail with a named error
        // that names the platform and every chunk's collected line count —
        // never a clean verdict over zero evidence.
        for platform in [LiveLabPlatform::Linux, LiveLabPlatform::MacOs] {
            let chunk_counts = if platform == LiveLabPlatform::MacOs {
                vec![0, 0, 0]
            } else {
                vec![0]
            };
            let refusal = secrets_zero_line_refusal(&platform, &chunk_counts).expect("must refuse");
            assert!(
                refusal.contains(platform.as_str()),
                "the refusal must name the platform: {refusal}"
            );
            for (idx, count) in chunk_counts.iter().enumerate() {
                assert!(
                    refusal.contains(&format!("chunk {idx} collected {count} lines")),
                    "the refusal must name each chunk's collected line count: {refusal}"
                );
            }
            assert!(
                refusal.contains("fail closed") && refusal.contains("impossible"),
                "the refusal must state that a pass is impossible: {refusal}"
            );
        }
        // Positive control: real collected evidence never refuses.
        assert!(secrets_zero_line_refusal(&LiveLabPlatform::MacOs, &[0, 12, 3]).is_none());
        assert!(secrets_zero_line_refusal(&LiveLabPlatform::Linux, &[500]).is_none());
        // And an empty slice (no chunks at all) is zero evidence too.
        assert!(secrets_zero_line_refusal(&LiveLabPlatform::Linux, &[]).is_some());
    }

    #[test]
    fn platform_parse_accepts_the_documented_tags() {
        assert_eq!(
            LiveLabPlatform::parse("macos").expect("macos"),
            LiveLabPlatform::MacOs
        );
        assert_eq!(
            LiveLabPlatform::parse("linux").expect("linux"),
            LiveLabPlatform::Linux
        );
        assert!(LiveLabPlatform::parse("plan9").is_err());
    }
}
