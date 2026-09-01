#![cfg_attr(not(test), allow(dead_code))]
// pure scanner+evaluator; live SecretsNotInLogs validator/daemon-subcommand wiring lands when the lab is up (GAP-6 §5/§8)
//! Offline core of the secrets-in-logs validation (GAP-6, design
//! `LiveLabCrossPlatformCustodySecretsAclStageDesign_2026-09-01.md` §5 + §7):
//! the canonical forbidden-secret scanner and the fail-closed report
//! evaluator, as pure logic with no I/O, no adapters, and no lab dependency.
//!
//! The forbidden pattern set is MIRRORED EXACTLY from the existing Linux
//! live binary `crates/rustynet-cli/src/bin/live_linux_secrets_not_in_logs_test.rs`
//! (design amendment A3 pins this set):
//! - 64-hex-character WireGuard private-key shapes (binary `scan_hex_pattern(…, 64)`, lines 184/248-274);
//! - 32-hex-character ed25519 key shapes (binary `scan_hex_pattern(…, 32)`, lines 185/248-274);
//! - base64 DER EC/ed25519 private-key header blocks (binary `scan_b64_ec_key_headers`,
//!   lines 276-291, prefixes pinned at line 280).
//!
//! The evaluator mirrors the fail-closed report-classification shape of the
//! key-custody evaluators (`evaluate_windows_key_custody_report` at
//! `crates/rustynet-cli/src/vm_lab/mod.rs:19585` and siblings): schema-version
//! check, per-check status, `overall_ok` consistency, empty-set rejection,
//! and malformed-JSON rejection. On top of that it enforces design amendment
//! A4: a report whose stimulus pathways were never exercised is a REPORTED
//! LIMITATION, never a pass — absent-secret evidence with zero stimulus is
//! rejected, not accepted.

use serde::Deserialize;

/// Canonical schema version of the secrets-not-in-logs report.
pub const SECRETS_NOT_IN_LOGS_SCHEMA_VERSION: u64 = 1;

/// One forbidden secret shape from the pinned set (A3).
pub struct SecretPattern {
    /// Stable identifier used in report check entries.
    pub name: &'static str,
    /// Human-readable description of what the shape is.
    pub description: &'static str,
    matcher: PatternMatcher,
}

enum PatternMatcher {
    /// A run of exactly this many ASCII hex digits, bounded by non-hex
    /// neighbors (mirrors `scan_hex_pattern`, binary lines 256-271).
    HexRun(usize),
    /// A base64-encoded DER key header prefix (mirrors
    /// `scan_b64_ec_key_headers`, binary lines 276-291).
    Base64DerPrefix(&'static str),
}

impl SecretPattern {
    /// True when this pattern occurs anywhere in `line`.
    pub fn matches_line(&self, line: &str) -> bool {
        match &self.matcher {
            PatternMatcher::HexRun(char_len) => line_contains_hex_run(line, *char_len),
            PatternMatcher::Base64DerPrefix(prefix) => line.contains(prefix),
        }
    }
}

/// The pinned forbidden-secret pattern set (design A3), mirrored from
/// `live_linux_secrets_not_in_logs_test.rs`. Any additional shape (enrollment
/// token formats, preshared-key fields, …) must be added here deliberately,
/// with its own detection test — never absorbed silently.
pub fn forbidden_secret_patterns() -> &'static [SecretPattern] {
    const PATTERNS: &[SecretPattern] = &[
        SecretPattern {
            name: "wireguard_private_key_hex64",
            description: "64-hex-character WireGuard 256-bit private-key shape",
            matcher: PatternMatcher::HexRun(64),
        },
        SecretPattern {
            name: "ed25519_key_hex32",
            description: "32-hex-character ed25519 signing-key shape",
            matcher: PatternMatcher::HexRun(32),
        },
        SecretPattern {
            name: "base64_ec_key_header",
            description: "base64 DER EC/ed25519 private-key header block",
            matcher: PatternMatcher::Base64DerPrefix("MC4CAQAwBQ"),
        },
        SecretPattern {
            name: "base64_sec1_ec_key_header",
            description: "base64 SEC1 EC private-key header block",
            matcher: PatternMatcher::Base64DerPrefix("MHQCAQEEI"),
        },
        SecretPattern {
            name: "base64_pkcs8_ec_key_header",
            description: "base64 PKCS#8 EC private-key header block",
            matcher: PatternMatcher::Base64DerPrefix("MIGHAgEA"),
        },
    ];
    PATTERNS
}

/// A forbidden-secret hit: which pattern matched, on which 1-based line.
/// A hit is a hard failure signal — a secret in a log is never a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHit {
    pub pattern_name: &'static str,
    pub line_number: usize,
}

/// Scan `log_text` line-by-line for every pinned forbidden-secret pattern.
///
/// Mirrors the Linux binary's collection semantics exactly: journalctl
/// `-- Boot ` / `-- Reboot ` separator lines are metadata, not daemon output,
/// and are skipped for the hex-run patterns (binary lines 251-255); the
/// base64 header scan does not skip them (binary lines 282-289). At most one
/// hit per pattern per line is reported, matching the binary's per-line
/// `break`.
pub fn scan_log_for_secrets(log_text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for (idx, line) in log_text.lines().enumerate() {
        let line_number = idx + 1;
        // journalctl inserts "-- Boot <boot-id> --" separator lines between
        // boots; the boot-id is not a secret (binary lines 251-255).
        let is_journal_separator = line.starts_with("-- Boot ") || line.starts_with("-- Reboot ");
        for pattern in forbidden_secret_patterns() {
            if matches!(pattern.matcher, PatternMatcher::HexRun(_)) && is_journal_separator {
                continue;
            }
            if pattern.matches_line(line) {
                hits.push(SecretHit {
                    pattern_name: pattern.name,
                    line_number,
                });
            }
        }
    }
    hits
}

/// Sliding-window hex-run detection with non-hex boundary confirmation,
/// mirroring `scan_hex_pattern` (binary lines 256-272) so a longer hex run
/// never produces a partial match inside itself.
fn line_contains_hex_run(line: &str, char_len: usize) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i + char_len <= bytes.len() {
        let window = &bytes[i..i + char_len];
        if window.iter().all(u8::is_ascii_hexdigit) {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
            let after_ok = i + char_len == bytes.len() || !bytes[i + char_len].is_ascii_hexdigit();
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// One per-pattern check entry in the secrets-not-in-logs report.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretsNotInLogsCheckEntry {
    /// Must name a pattern from [`forbidden_secret_patterns`].
    pub name: String,
    /// Explicit per-check status; only `ok` is acceptable.
    pub status: String,
    /// Number of forbidden-pattern hits found for this pattern.
    #[serde(default)]
    pub secret_hits: u64,
    /// A4: evidence that this check's stimulus pathway was actually driven.
    /// Absent or false means the check could assert nothing.
    #[serde(default)]
    pub pathway_exercised: Option<bool>,
}

/// The secrets-not-in-logs report produced by a validator run.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretsNotInLogsReport {
    pub schema_version: u64,
    pub overall_ok: bool,
    /// Failure/drift reasons; must be empty exactly when `overall_ok` is true.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// A4: how many stimulus pathways the run actually exercised. Zero (or
    /// absent) means no evidence was generated at all.
    #[serde(default)]
    pub pathways_exercised: Option<u64>,
    #[serde(default)]
    pub checks: Vec<SecretsNotInLogsCheckEntry>,
}

/// Fail-closed evaluator for a secrets-not-in-logs report (design §5.1/§7).
///
/// Accepts ONLY a report that: parses as JSON; carries schema version
/// [`SECRETS_NOT_IN_LOGS_SCHEMA_VERSION`]; names every pinned pattern with an
/// explicit `ok` check; records zero secret hits per check; kept
/// `overall_ok` consistent with its reasons; AND carries A4 stimulus
/// evidence (`pathways_exercised >= 1` with every check's pathway driven).
/// Every rejection names its reason.
pub fn evaluate_secrets_not_in_logs_report(report_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(report_json)
        .map_err(|err| format!("parse secrets-not-in-logs report JSON failed: {err}"))?;
    let schema_field = value
        .get("schema_version")
        .ok_or_else(|| "secrets-not-in-logs report missing schema_version; rejecting".to_owned())?;
    let schema_version = schema_field.as_u64().ok_or_else(|| {
        format!(
            "secrets-not-in-logs report schema_version is not an unsigned integer: {schema_field}"
        )
    })?;
    if schema_version != SECRETS_NOT_IN_LOGS_SCHEMA_VERSION {
        return Err(format!(
            "secrets-not-in-logs report returned unsupported schema_version={schema_version}"
        ));
    }
    let report: SecretsNotInLogsReport = serde_json::from_value(value)
        .map_err(|err| format!("secrets-not-in-logs report has invalid fields: {err}"))?;

    if report.checks.is_empty() {
        return Err(
            "secrets-not-in-logs report returned an empty checks list; expected the canonical \
             forbidden-secret pattern set"
                .to_owned(),
        );
    }

    // Every pinned pattern must be explicitly checked — a silently absent
    // pattern is an unscanned pattern, which fails closed.
    let expected: Vec<&str> = forbidden_secret_patterns()
        .iter()
        .map(|pattern| pattern.name)
        .collect();
    for expected_name in &expected {
        if !report
            .checks
            .iter()
            .any(|check| check.name == *expected_name)
        {
            return Err(format!(
                "secrets-not-in-logs report is missing check for forbidden pattern '{expected_name}'"
            ));
        }
    }

    // Per-check validation: explicit ok status, zero hits, exercised pathway.
    for check in &report.checks {
        if !expected.contains(&check.name.as_str()) {
            return Err(format!(
                "secrets-not-in-logs report carries unknown check '{}' outside the pinned pattern set",
                check.name
            ));
        }
        if check.status != "ok" {
            return Err(format!(
                "secrets-not-in-logs drift detected: check '{}' status '{}'",
                check.name, check.status
            ));
        }
        if check.secret_hits > 0 {
            return Err(format!(
                "secrets-not-in-logs check '{}' found {} secret hit(s) in the log; a secret in a log is never a warning",
                check.name, check.secret_hits
            ));
        }
        if check.pathway_exercised != Some(true) {
            return Err(format!(
                "secrets-not-in-logs check '{}' records no exercised stimulus pathway; an \
                 absent-secret result without stimulus is a reported limitation, never a pass \
                 (design A4)",
                check.name
            ));
        }
    }

    if !report.overall_ok {
        let reasons = if report.reasons.is_empty() {
            "report set overall_ok=false but no reasons recorded; output is inconsistent".to_owned()
        } else {
            report.reasons.join("; ")
        };
        return Err(format!("secrets-not-in-logs drift detected: {reasons}"));
    }
    if !report.reasons.is_empty() {
        return Err(format!(
            "secrets-not-in-logs report set overall_ok=true but reasons is non-empty: {}",
            report.reasons.join("; ")
        ));
    }

    // A4 guard: zero exercised stimulus pathways means the run scanned a log
    // it never gave a reason to contain secrets. That is a limitation to be
    // reported, never a pass.
    let pathways = report.pathways_exercised.unwrap_or(0);
    if pathways == 0 {
        return Err(
            "secrets-not-in-logs report records zero exercised stimulus pathways; an \
             absent-secret result without stimulus is a reported limitation, never a pass \
             (design A4)"
                .to_owned(),
        );
    }

    Ok(format!(
        "secrets-not-in-logs verified: {} forbidden patterns scanned clean across {} exercised stimulus pathways",
        report.checks.len(),
        pathways
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_run(len: usize) -> String {
        "0123456789abcdef".chars().cycle().take(len).collect()
    }

    // ── Scanner detection: one test per pinned pattern shape ────────────────

    #[test]
    fn detects_wireguard_hex64_key_shape() {
        let log = format!(
            "rustynetd: tunnel up\nkey blob was {}\nnext line\n",
            hex_run(64)
        );
        let hits = scan_log_for_secrets(&log);
        let hit = hits
            .iter()
            .find(|hit| hit.pattern_name == "wireguard_private_key_hex64")
            .expect("64-hex WireGuard key shape must be detected");
        assert_eq!(hit.line_number, 2);
    }

    #[test]
    fn detects_ed25519_hex32_key_shape() {
        let log = format!("signing key {}\nbenign\n", hex_run(32));
        let hits = scan_log_for_secrets(&log);
        let hit = hits
            .iter()
            .find(|hit| hit.pattern_name == "ed25519_key_hex32")
            .expect("32-hex ed25519 key shape must be detected");
        assert_eq!(hit.line_number, 1);
        assert!(
            !hits
                .iter()
                .any(|hit| hit.pattern_name == "wireguard_private_key_hex64"),
            "a 32-hex run must not also count as a 64-hex shape"
        );
    }

    #[test]
    fn detects_base64_ec_key_header_blocks() {
        let log = "MC4CAQAwBQsomeblob\nMHQCAQEEIotherblob\nMIGHAgEAthirdblob\n";
        let hits = scan_log_for_secrets(log);
        for expected in [
            "base64_ec_key_header",
            "base64_sec1_ec_key_header",
            "base64_pkcs8_ec_key_header",
        ] {
            assert!(
                hits.iter().any(|hit| hit.pattern_name == expected),
                "base64 DER key-header shape '{expected}' must be detected"
            );
        }
        assert!(hits.iter().all(|hit| hit.line_number >= 1));
    }

    #[test]
    fn clean_log_produces_zero_hits() {
        let log = "rustynetd: handshake complete\n\
                   -- Boot 3f2a1c9b8d7e4f60a1b2c3d4e5f60718 --\n\
                   role=client peer=7 confirmed\n\
                   token len=64 (redacted)\n";
        assert!(
            scan_log_for_secrets(log).is_empty(),
            "a benign log must produce zero hits"
        );
    }

    #[test]
    fn hex_run_is_not_detected_inside_longer_hex_token() {
        // A 96-hex token must not yield a partial 64- or 32-hex match
        // (boundary confirmation, binary lines 262-264).
        let log = format!("oversized token {}\n", hex_run(96));
        assert!(
            scan_log_for_secrets(&log).is_empty(),
            "partial hex matches inside longer tokens must not fire"
        );
    }

    // ── Report fixtures ─────────────────────────────────────────────────────

    fn check_entry(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "status": "ok",
            "secret_hits": 0,
            "pathway_exercised": true,
        })
    }

    fn all_ok_report() -> serde_json::Value {
        serde_json::json!({
            "schema_version": SECRETS_NOT_IN_LOGS_SCHEMA_VERSION,
            "overall_ok": true,
            "reasons": [],
            "pathways_exercised": 2,
            "checks": forbidden_secret_patterns()
                .iter()
                .map(|pattern| check_entry(pattern.name))
                .collect::<Vec<_>>(),
        })
    }

    // ── Evaluator fail-closed matrix (mirrors the key-custody evaluators) ───

    #[test]
    fn accepts_all_ok_report_with_exercised_pathways() {
        let summary = evaluate_secrets_not_in_logs_report(&all_ok_report().to_string())
            .expect("an all-ok report with exercised pathways must pass");
        assert!(summary.contains("verified"));
    }

    #[test]
    fn rejects_drifted_check_with_named_reason() {
        let mut report = all_ok_report();
        report["checks"][1]["status"] = serde_json::json!("drift");
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("a drifted check must fail the evaluator");
        assert!(
            err.contains("drift detected")
                && err.contains(&forbidden_secret_patterns()[1].name.to_string()),
            "should name the drifted check, got: {err}"
        );
    }

    #[test]
    fn rejects_report_with_secret_hits_even_when_marked_ok() {
        let mut report = all_ok_report();
        report["checks"][0]["secret_hits"] = serde_json::json!(1);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("a check with secret hits must fail even when status=ok");
        assert!(
            err.contains("secret hit"),
            "should reject hits as a hard failure, got: {err}"
        );
    }

    #[test]
    fn rejects_missing_check_entry() {
        let mut report = all_ok_report();
        report["checks"].as_array_mut().expect("array").pop();
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("a missing pattern check must fail closed");
        assert!(
            err.contains("missing check for forbidden pattern"),
            "should name the missing pattern, got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut report = all_ok_report();
        report["schema_version"] = serde_json::json!(999);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("an unknown schema version must be rejected");
        assert!(
            err.contains("unsupported schema_version=999"),
            "should reject unsupported schema version, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_check_set() {
        let mut report = all_ok_report();
        report["checks"] = serde_json::json!([]);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("an empty check set must be rejected");
        assert!(
            err.contains("empty checks list"),
            "should reject the empty check set, got: {err}"
        );
    }

    #[test]
    fn rejects_inconsistent_overall_ok_true_with_drift_reasons() {
        let mut report = all_ok_report();
        report["reasons"] = serde_json::json!(["journal capture failed"]);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("overall_ok=true alongside reasons must be rejected");
        assert!(
            err.contains("overall_ok=true but reasons is non-empty"),
            "should reject the inconsistent overall_ok, got: {err}"
        );
    }

    #[test]
    fn rejects_malformed_json() {
        let err = evaluate_secrets_not_in_logs_report("{not json")
            .expect_err("malformed JSON must be rejected");
        assert!(
            err.contains("parse secrets-not-in-logs report JSON failed"),
            "should reject malformed JSON, got: {err}"
        );
    }

    // ── A4 guard: no-stimulus-is-not-a-pass ─────────────────────────────────

    #[test]
    fn absent_secret_without_stimulus_is_not_a_pass() {
        let mut report = all_ok_report();
        report["pathways_exercised"] = serde_json::json!(0);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("zero exercised pathways must never read as a pass (design A4)");
        assert!(
            err.contains("zero exercised stimulus pathways") && err.contains("limitation"),
            "should classify no-stimulus as limitation-not-pass, got: {err}"
        );

        let mut absent = all_ok_report();
        absent
            .as_object_mut()
            .expect("object")
            .remove("pathways_exercised");
        let err = evaluate_secrets_not_in_logs_report(&absent.to_string())
            .expect_err("an absent pathway count must fail closed too");
        assert!(
            err.contains("zero exercised stimulus pathways"),
            "should treat a missing pathway count as zero, got: {err}"
        );
    }

    #[test]
    fn unexercised_per_check_pathway_is_a_limitation_not_a_pass() {
        let mut report = all_ok_report();
        report["checks"][2]["pathway_exercised"] = serde_json::json!(false);
        let err = evaluate_secrets_not_in_logs_report(&report.to_string())
            .expect_err("a check whose pathway was not driven must not pass on absence");
        assert!(
            err.contains("no exercised stimulus pathway"),
            "should reject the unexercised check, got: {err}"
        );
    }
}
