#![allow(clippy::result_large_err)]

//! macOS exit-mode killswitch precedence artefact producer.
//!
//! Emits the schema-v1 `macos_exit_killswitch_precedence.json` report
//! consumed by `evaluate_macos_exit_killswitch_precedence_artifact`.
//! Runtime capture is intentionally narrow: snapshot the active
//! RustyNet pf anchor, flush it, prove the killswitch assertion fails,
//! then restore the exact captured rules before returning.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

pub const MACOS_EXIT_KILLSWITCH_PRECEDENCE_SCHEMA_VERSION: u32 = 1;
pub const MACOS_RUSTYNET_ANCHOR_PREFIX: &str = "com.apple/rustynet_g";

/// Bounded retry budget for live anchor discovery. The macOS killswitch anchor
/// (`com.apple/rustynet_g<N>`) rotates its generation on every (re-)apply, so a
/// single-shot `pfctl -s Anchors` sample can land in the rotation window with no
/// matching anchor present. Poll up to this many attempts, sleeping
/// `MACOS_ANCHOR_POLL_INTERVAL` between tries, returning as soon as one matches.
/// The budget is finite by construction (a `for` over a fixed count), so it can
/// never spin forever; once exhausted it fails closed with the original error.
#[cfg(target_os = "macos")]
const MACOS_ANCHOR_POLL_ATTEMPTS: u32 = 15;
// Compile-time invariant: the poll budget must be finite and positive so the
// anchor poll loop is always bounded (fail-closed termination). A const assert
// catches an accidental zero/unbounded budget at build time — stronger than a
// runtime test. Gated to macOS to match the constant it checks (the const is
// `cfg(target_os = "macos")`, so an ungated assert is an E0425 on Linux).
#[cfg(target_os = "macos")]
const _: () = assert!(MACOS_ANCHOR_POLL_ATTEMPTS > 0 && MACOS_ANCHOR_POLL_ATTEMPTS <= 60);
#[cfg(target_os = "macos")]
const MACOS_ANCHOR_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The exact error returned when no live RustyNet macOS pf anchor is ever found.
/// Shared so the bounded poll path and any caller assert on the identical text.
pub const MACOS_NO_ACTIVE_ANCHOR_ERROR: &str = "no active RustyNet macOS pf anchor found";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosExitKillswitchPrecedenceOptions {
    pub pf_anchor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosKillswitchAssertReport {
    pub overall_ok: bool,
    pub exit_code: i32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitKillswitchPrecedenceReport {
    pub schema_version: u32,
    pub pf_anchor: String,
    pub baseline_assert: MacosKillswitchAssertReport,
    pub tampered_assert: MacosKillswitchAssertReport,
}

pub fn write_macos_exit_killswitch_precedence_report(
    output_path: &Path,
    options: &MacosExitKillswitchPrecedenceOptions,
) -> Result<(), String> {
    let report = collect_macos_exit_killswitch_precedence_report(options)?;
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    let encoded = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("serialize macos killswitch precedence report failed: {err}"))?;
    fs::write(output_path, encoded).map_err(|err| {
        format!(
            "write macos killswitch precedence report {} failed: {err}",
            output_path.display()
        )
    })?;
    if !report.baseline_assert.overall_ok {
        return Err(format!(
            "baseline macOS killswitch assertion failed: {}",
            report.baseline_assert.reason
        ));
    }
    if report.tampered_assert.overall_ok || report.tampered_assert.exit_code == 0 {
        return Err("tampered macOS killswitch assertion unexpectedly passed".to_owned());
    }
    Ok(())
}

pub fn build_macos_exit_killswitch_precedence_report(
    pf_anchor: &str,
    baseline_rules: &str,
    tampered_rules: &str,
) -> MacosExitKillswitchPrecedenceReport {
    MacosExitKillswitchPrecedenceReport {
        schema_version: MACOS_EXIT_KILLSWITCH_PRECEDENCE_SCHEMA_VERSION,
        pf_anchor: pf_anchor.to_owned(),
        baseline_assert: build_macos_killswitch_assert_report(baseline_rules),
        tampered_assert: build_macos_killswitch_assert_report(tampered_rules),
    }
}

pub fn build_macos_killswitch_assert_report(rules: &str) -> MacosKillswitchAssertReport {
    match evaluate_macos_killswitch_rules(rules) {
        Ok(()) => MacosKillswitchAssertReport {
            overall_ok: true,
            exit_code: 0,
            reason: "macOS pf killswitch rule present".to_owned(),
        },
        Err(reason) => MacosKillswitchAssertReport {
            overall_ok: false,
            exit_code: 2,
            reason,
        },
    }
}

pub fn evaluate_macos_killswitch_rules(rules: &str) -> Result<(), String> {
    let has_block_all = rules.lines().any(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized.eq_ignore_ascii_case("block drop out quick all")
            || normalized
                .to_ascii_lowercase()
                .contains("block drop out quick all")
    });
    if has_block_all {
        Ok(())
    } else {
        Err("macOS pf killswitch verification failed: block drop out quick all missing".to_owned())
    }
}

pub fn select_macos_rustynet_anchor(pfctl_anchors_stdout: &str) -> Option<String> {
    pfctl_anchors_stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(MACOS_RUSTYNET_ANCHOR_PREFIX))
        .filter(|line| validate_pf_anchor_name(line).is_ok())
        .max_by_key(|line| parse_generation(line).unwrap_or(0))
        .map(ToOwned::to_owned)
}

pub fn validate_pf_anchor_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || value.contains("..")
        || value.starts_with('/')
        || value.ends_with('/')
    {
        return Err("pf anchor name contains unsupported characters".to_owned());
    }
    Ok(())
}

fn parse_generation(value: &str) -> Option<u64> {
    value
        .strip_prefix(MACOS_RUSTYNET_ANCHOR_PREFIX)?
        .parse::<u64>()
        .ok()
}

/// The outcome of one anchor-discovery poll sample, given the `pfctl -s Anchors`
/// stdout for that attempt and whether the retry budget still has tries left.
/// Pure so the retry decision is unit-testable without invoking `pfctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorPollOutcome {
    /// An anchor matched on this sample: stop polling and use it.
    Found(String),
    /// No match yet but the budget is not exhausted: sleep and try again.
    Retry,
    /// No match and the budget is exhausted: fail closed.
    GiveUp,
}

/// Decide the next step after one poll sample. Returns [`AnchorPollOutcome::Found`]
/// the instant any valid rotated `com.apple/rustynet_g<N>` anchor appears,
/// [`AnchorPollOutcome::Retry`] while tries remain, and
/// [`AnchorPollOutcome::GiveUp`] only once the bounded budget is spent. This is
/// what keeps the loop both race-tolerant and fail-closed.
pub fn classify_anchor_poll_sample(
    pfctl_anchors_stdout: &str,
    has_more_attempts: bool,
) -> AnchorPollOutcome {
    match select_macos_rustynet_anchor(pfctl_anchors_stdout) {
        Some(anchor) => AnchorPollOutcome::Found(anchor),
        None if has_more_attempts => AnchorPollOutcome::Retry,
        None => AnchorPollOutcome::GiveUp,
    }
}

/// Bounded poll for a live RustyNet macOS pf anchor. Re-samples
/// `pfctl -s Anchors` up to `MACOS_ANCHOR_POLL_ATTEMPTS` times (sleeping
/// `MACOS_ANCHOR_POLL_INTERVAL` between tries) to close the generation-rotation
/// window, returning the matching anchor as soon as one appears. The loop bound
/// is a fixed `for` range so it always terminates; if no anchor ever shows up
/// the budget is exhausted and it fails closed with `MACOS_NO_ACTIVE_ANCHOR_ERROR`.
#[cfg(target_os = "macos")]
fn poll_for_macos_rustynet_anchor() -> Result<String, String> {
    for attempt in 0..MACOS_ANCHOR_POLL_ATTEMPTS {
        let anchors = run_pfctl(&["-s", "Anchors"])?;
        let has_more_attempts = attempt + 1 < MACOS_ANCHOR_POLL_ATTEMPTS;
        match classify_anchor_poll_sample(anchors.as_str(), has_more_attempts) {
            AnchorPollOutcome::Found(anchor) => return Ok(anchor),
            AnchorPollOutcome::Retry => std::thread::sleep(MACOS_ANCHOR_POLL_INTERVAL),
            AnchorPollOutcome::GiveUp => break,
        }
    }
    Err(MACOS_NO_ACTIVE_ANCHOR_ERROR.to_owned())
}

#[cfg(target_os = "macos")]
fn collect_macos_exit_killswitch_precedence_report(
    options: &MacosExitKillswitchPrecedenceOptions,
) -> Result<MacosExitKillswitchPrecedenceReport, String> {
    let anchor = match options.pf_anchor.as_deref() {
        Some(anchor) => {
            validate_pf_anchor_name(anchor)?;
            anchor.to_owned()
        }
        None => poll_for_macos_rustynet_anchor()?,
    };
    validate_pf_anchor_name(anchor.as_str())?;

    let baseline_rules = run_pfctl(&["-a", anchor.as_str(), "-s", "rules"])?;
    let baseline_assert = build_macos_killswitch_assert_report(baseline_rules.as_str());
    if !baseline_assert.overall_ok {
        return Ok(MacosExitKillswitchPrecedenceReport {
            schema_version: MACOS_EXIT_KILLSWITCH_PRECEDENCE_SCHEMA_VERSION,
            pf_anchor: anchor,
            baseline_assert,
            tampered_assert: build_macos_killswitch_assert_report(""),
        });
    }

    let restore_path = write_restore_file(anchor.as_str(), baseline_rules.as_str())?;
    let mut restore_error: Option<String> = None;
    let tampered_result = (|| {
        run_pfctl_status(&["-a", anchor.as_str(), "-F", "all"])?;
        let tampered_rules = run_pfctl(&["-a", anchor.as_str(), "-s", "rules"])?;
        Ok::<_, String>(build_macos_killswitch_assert_report(
            tampered_rules.as_str(),
        ))
    })();

    let restore_result = run_pfctl_status(&[
        "-a",
        anchor.as_str(),
        "-f",
        restore_path.to_string_lossy().as_ref(),
    ]);
    if let Err(err) = restore_result {
        restore_error = Some(err);
    }
    let _ = fs::remove_file(&restore_path);

    if let Some(err) = restore_error {
        return Err(format!(
            "restore macOS pf anchor {anchor} after tamper failed: {err}"
        ));
    }

    let tampered_assert = tampered_result?;
    Ok(MacosExitKillswitchPrecedenceReport {
        schema_version: MACOS_EXIT_KILLSWITCH_PRECEDENCE_SCHEMA_VERSION,
        pf_anchor: anchor,
        baseline_assert,
        tampered_assert,
    })
}

#[cfg(not(target_os = "macos"))]
fn collect_macos_exit_killswitch_precedence_report(
    options: &MacosExitKillswitchPrecedenceOptions,
) -> Result<MacosExitKillswitchPrecedenceReport, String> {
    let anchor = options
        .pf_anchor
        .clone()
        .unwrap_or_else(|| format!("{MACOS_RUSTYNET_ANCHOR_PREFIX}1"));
    validate_pf_anchor_name(anchor.as_str())?;
    Ok(build_macos_exit_killswitch_precedence_report(
        anchor.as_str(),
        "",
        "",
    ))
}

#[cfg(target_os = "macos")]
fn run_pfctl(args: &[&str]) -> Result<String, String> {
    let output = Command::new("/sbin/pfctl")
        .args(args)
        .output()
        .map_err(|err| format!("pfctl {} failed to start: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "pfctl {} failed: status={} stderr={}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn run_pfctl_status(args: &[&str]) -> Result<(), String> {
    run_pfctl(args).map(|_| ())
}

#[cfg(target_os = "macos")]
fn write_restore_file(anchor: &str, rules: &str) -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "rustynet-macos-killswitch-{}-{now}.pf",
        anchor.replace(['/', '.'], "_")
    ));
    fs::write(&path, rules)
        .map_err(|err| format!("write restore pf rules {} failed: {err}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn killswitch_assert_accepts_reviewed_block_all_rule() {
        let report = build_macos_killswitch_assert_report(
            "pass out quick inet on utun9 all keep state\nblock drop out quick all\n",
        );
        assert!(report.overall_ok);
        assert_eq!(report.exit_code, 0);
    }

    #[test]
    fn killswitch_assert_fails_closed_when_block_all_missing() {
        let report = build_macos_killswitch_assert_report("pass out quick inet on utun9 all\n");
        assert!(!report.overall_ok);
        assert_eq!(report.exit_code, 2);
        assert!(report.reason.contains("block drop out quick all missing"));
    }

    #[test]
    fn precedence_report_matches_validator_shape() {
        let report = build_macos_exit_killswitch_precedence_report(
            "com.apple/rustynet_g7",
            "block drop out quick all\n",
            "",
        );
        assert_eq!(report.schema_version, 1);
        assert!(report.baseline_assert.overall_ok);
        assert!(!report.tampered_assert.overall_ok);
        assert_ne!(report.tampered_assert.exit_code, 0);
        assert!(!report.tampered_assert.reason.trim().is_empty());
    }

    #[test]
    fn anchor_selection_picks_highest_generation() {
        let stdout = "com.apple/rustynet_g1\ncom.apple/rustynet_g12\ncom.apple/rustynet_g3\n";
        assert_eq!(
            select_macos_rustynet_anchor(stdout).as_deref(),
            Some("com.apple/rustynet_g12")
        );
    }

    #[test]
    fn anchor_validation_rejects_shell_metacharacters_and_traversal() {
        assert!(validate_pf_anchor_name("com.apple/rustynet_g1").is_ok());
        assert!(validate_pf_anchor_name("com.apple/rustynet_g1;rm").is_err());
        assert!(validate_pf_anchor_name("../com.apple/rustynet_g1").is_err());
    }

    #[test]
    fn anchor_selection_matches_rotated_generation_names() {
        // The killswitch anchor rotates its generation on every (re-)apply; the
        // selector must still match each rotated `com.apple/rustynet_g<N>` name
        // and pick the highest generation. This guards the retry loop's premise.
        for generation in [0u64, 1, 9, 42, 1000] {
            let line = format!("{MACOS_RUSTYNET_ANCHOR_PREFIX}{generation}");
            assert_eq!(
                select_macos_rustynet_anchor(line.as_str()).as_deref(),
                Some(line.as_str()),
                "rotated anchor generation {generation} must match",
            );
        }
    }

    #[test]
    fn poll_sample_returns_found_immediately_when_anchor_present() {
        // A matching anchor short-circuits the poll regardless of remaining budget.
        let stdout = "com.apple/rustynet_g4\n";
        assert_eq!(
            classify_anchor_poll_sample(stdout, true),
            AnchorPollOutcome::Found("com.apple/rustynet_g4".to_owned()),
        );
        assert_eq!(
            classify_anchor_poll_sample(stdout, false),
            AnchorPollOutcome::Found("com.apple/rustynet_g4".to_owned()),
        );
    }

    #[test]
    fn poll_sample_retries_within_budget_then_gives_up() {
        // No anchor + tries remaining => Retry (close the rotation window).
        assert_eq!(
            classify_anchor_poll_sample("", true),
            AnchorPollOutcome::Retry,
        );
        // No anchor + budget exhausted => GiveUp (fail closed, bounded).
        assert_eq!(
            classify_anchor_poll_sample("", false),
            AnchorPollOutcome::GiveUp,
        );
        // Non-matching noise is treated as "no anchor" the same way.
        assert_eq!(
            classify_anchor_poll_sample("com.apple/250.ApplicationFirewall\n", false),
            AnchorPollOutcome::GiveUp,
        );
    }

    // The poll-budget bound invariant (0 < ATTEMPTS <= 60) is enforced as a
    // compile-time `const _` assertion at the constant's definition site above,
    // which is stronger than a runtime test and platform-independent.
}
