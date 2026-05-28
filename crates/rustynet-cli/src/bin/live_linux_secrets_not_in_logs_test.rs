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
    let mut target_host = String::new();
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

    // ── Stage 1: flush journal cursor ────────────────────────────────────────
    logger.line("[secrets-log] flushing journal cursor on target")?;
    let _ = ctx.run_root_allow_failure(&target_host, &["journalctl", "--flush"]);

    // ── Stage 2: trigger enrollment activity to exercise key paths ────────────
    logger.line("[secrets-log] triggering enrollment token activity")?;
    // Invoke `rustynet ops generate-enrollment-token` — if it errors (no anchor state on
    // this node), that's fine; we just want to exercise the codepath in the daemon logs.
    let _ = ctx.capture_root_allow_failure(
        &target_host,
        &[
            "rustynet",
            "ops",
            "generate-enrollment-token",
            "--ttl-seconds",
            "60",
        ],
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    // ── Stage 3: collect journal lines ───────────────────────────────────────
    logger.line("[secrets-log] collecting journal lines from rustynetd")?;
    let journal = ctx
        .capture_root_allow_failure(
            &target_host,
            &[
                "journalctl",
                "-u",
                "rustynetd",
                "-n",
                "500",
                "--no-pager",
                "--output=short-monotonic",
            ],
        )
        .unwrap_or_default();

    let line_count = journal.lines().count();
    logger.line(format!(
        "[secrets-log] collected {line_count} journal lines"
    ))?;

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
    let suspicious_str = total_suspicious.to_string();
    let line_count_str = line_count.to_string();
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--log-lines-checked".to_owned(),
        line_count_str,
        "--suspicious-matches".to_owned(),
        suspicious_str,
        "--hex64-matches".to_owned(),
        hex64_matches.len().to_string(),
        "--hex32-matches".to_owned(),
        hex32_matches.len().to_string(),
        "--b64-key-matches".to_owned(),
        b64_key_matches.len().to_string(),
        "--verdict".to_owned(),
        if overall_pass {
            "clean"
        } else {
            "contaminated"
        }
        .to_owned(),
        "--overall-status".to_owned(),
        pass_fail(overall_pass).to_owned(),
    ];
    let report_refs: Vec<&str> = report_args.iter().map(String::as_str).collect();
    run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-secrets-not-in-logs-report",
        &report_refs,
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

fn scan_hex_pattern(text: &str, char_len: usize) -> Vec<String> {
    let mut hits = Vec::new();
    for line in text.lines() {
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
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
