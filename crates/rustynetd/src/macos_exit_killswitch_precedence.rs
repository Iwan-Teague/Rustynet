#![allow(clippy::result_large_err)]

//! macOS exit-mode killswitch precedence artefact producer.
//!
//! Emits the schema-v1 `macos_exit_killswitch_precedence.json` report
//! consumed by `evaluate_macos_exit_killswitch_precedence_artifact`.
//! Runtime capture is intentionally narrow: snapshot the active
//! RustyNet pf anchor, flush it, prove the killswitch assertion fails,
//! then restore the exact captured rules before returning.

use crate::killswitch_precedence::{
    ContainedInterfaces, ContainmentFailure, RuleDisposition, terminator_is_reachable,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

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

/// Verify the macOS pf killswitch actually CONTAINS general egress.
///
/// # Presence is not precedence (PF-05)
///
/// This used to be a substring search for `block drop out quick all` anywhere
/// in the ruleset. pf evaluates rules top to bottom and `quick` takes effect
/// immediately, so a `pass out quick` rule ABOVE the block wins outright and the
/// block never fires — while the assertion, finding the block's text present,
/// reported the killswitch verified. That is why the permissive-rule defects on
/// this backend were silent: this function was their alibi.
///
/// The ruleset is now walked in evaluation order (for pf, textual order) via
/// [`crate::killswitch_precedence`], and the block is credited only if it is
/// actually REACHABLE.
///
/// # Only `quick` passes above the block can defeat it
///
/// This is what makes the check precise rather than merely strict. Because the
/// terminator itself carries `quick`, it wins against any non-`quick` pass
/// regardless of order — pf's last-match-wins rule never gets to apply. So a
/// non-`quick` pass is genuinely harmless here and reporting it would be a
/// false positive. Only a `quick` pass, positioned above the block, and broader
/// than an allowlisted shape, actually breaks containment.
pub fn evaluate_macos_killswitch_rules(rules: &str) -> Result<(), String> {
    let contained = ContainedInterfaces::default();
    let lines: Vec<&str> = rules.lines().collect();
    terminator_is_reachable(&lines, |rule| classify_pf_egress_rule(rule, &contained)).map_err(
        |failure| match failure {
            ContainmentFailure::NoTerminator(_) => {
                "macOS pf killswitch verification failed: block drop out quick all missing"
                    .to_owned()
            }
            ContainmentFailure::Escaped(violation) => format!(
                "macOS pf killswitch verification failed: {violation}; a `quick` pass above \
                 `block drop out quick all` wins outright, so the block never fires"
            ),
        },
    )
}

/// Reduce one pf rule to its effect on general outbound traffic.
///
/// Fail-closed: a `quick` pass that cannot be proven narrow or tunnel-scoped is
/// [`RuleDisposition::Escapes`].
pub fn classify_pf_egress_rule(rule: &str, contained: &ContainedInterfaces) -> RuleDisposition {
    let normalized = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    let lowered = normalized.to_ascii_lowercase();
    if lowered.is_empty() || lowered.starts_with('#') {
        return RuleDisposition::Irrelevant;
    }
    // The terminator: the canonical all-traffic outbound block.
    if lowered.contains("block drop out quick all") {
        return RuleDisposition::Terminator;
    }
    // Any other block only tightens the posture.
    if lowered.starts_with("block") {
        return RuleDisposition::Irrelevant;
    }
    if !lowered.starts_with("pass") {
        // `scrub`, `nat`, `rdr`, `anchor`, `set`, `table`: not a filter verdict
        // on egress. `route-to` on a pass is handled below.
        return RuleDisposition::Irrelevant;
    }
    // Inbound rules cannot leak outbound traffic.
    if lowered.starts_with("pass in") {
        return RuleDisposition::Irrelevant;
    }
    // A pass WITHOUT `quick` loses to the terminator, which has it. pf's
    // last-match-wins never applies once a quick rule matches.
    if !lowered.split(' ').any(|token| token == "quick") {
        return RuleDisposition::Irrelevant;
    }
    // `route-to`/`reply-to`/`dup-to` force traffic out a named interface,
    // bypassing the routing table entirely. Never creditable.
    if ["route-to", "reply-to", "dup-to"]
        .iter()
        .any(|primitive| lowered.contains(primitive))
    {
        return RuleDisposition::Escapes;
    }
    // A quick pass bound to the tunnel (or loopback) is how encrypted traffic
    // legitimately leaves.
    if let Some(interface) = pf_rule_interface(&normalized)
        && contained.contains(interface)
    {
        return RuleDisposition::Contained;
    }
    // A quick pass narrowed to one service or source range is an operator
    // allowlist entry, not a general escape. See RuleDisposition::NarrowAllow
    // for the limits of that judgement.
    if pf_rule_is_narrowly_scoped(&lowered) {
        return RuleDisposition::NarrowAllow;
    }
    // What remains is an interface-wide or unrestricted quick pass — the shape
    // that silently disables the killswitch.
    RuleDisposition::Escapes
}

/// Extract the `on <interface>` argument of a pf rule, if present.
fn pf_rule_interface(rule: &str) -> Option<&str> {
    let mut tokens = rule.split(' ');
    while let Some(token) = tokens.next() {
        if token == "on" {
            // `on { en0 en1 }` is an interface list; a list containing anything
            // uncontained must not be credited, so decline to name one.
            return tokens.next().filter(|name| *name != "{");
        }
    }
    None
}

/// Whether a pass rule is restricted to a specific service or address range
/// rather than permitting a whole interface or all traffic.
fn pf_rule_is_narrowly_scoped(lowered: &str) -> bool {
    // A specific port is a service allowlist (the WireGuard endpoint, DNS).
    let has_port = lowered.contains(" port ");
    // A source or destination that is not `any`/`all` bounds the rule. The
    // blind_exit and exit-NAT rules take the `from <mesh_cidr> to any` shape.
    let bounded_source = lowered
        .split(" from ")
        .nth(1)
        .map(|rest| {
            let value = rest.split(' ').next().unwrap_or("");
            !value.is_empty() && value != "any" && value != "all"
        })
        .unwrap_or(false);
    let bounded_destination = lowered
        .split(" to ")
        .nth(1)
        .map(|rest| {
            let value = rest.split(' ').next().unwrap_or("");
            !value.is_empty() && value != "any" && value != "all"
        })
        .unwrap_or(false);
    has_port || bounded_source || bounded_destination
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

/// Return ALL valid `com.apple/rustynet_g<N>` anchors present in the
/// `pfctl -s Anchors` output, sorted by generation descending (newest first).
///
/// Unlike [`select_macos_rustynet_anchor`] which returns only the single
/// highest-generation anchor, this returns every matched anchor so callers can
/// probe each one. When a daemon restart leaves an old anchor (with rules) still
/// present while the new higher-generation anchor is still empty, probing only
/// the highest-gen anchor misses the still-in-force rules on the sibling anchor
/// — a false negative.
pub fn select_macos_rustynet_anchors(pfctl_anchors_stdout: &str) -> Vec<String> {
    let mut candidates: Vec<(u64, String)> = pfctl_anchors_stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(MACOS_RUSTYNET_ANCHOR_PREFIX))
        .filter(|line| validate_pf_anchor_name(line).is_ok())
        .filter_map(|line| {
            let gen_n = parse_generation(line)?;
            Some((gen_n, line.to_owned()))
        })
        .collect();
    candidates.sort_by_key(|(gen_n, _)| *gen_n);
    candidates.reverse();
    candidates.into_iter().map(|(_, anchor)| anchor).collect()
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
///
/// Fixed-interval polling is deliberately independent of
/// `resilience::next_reconnect_delay_jittered_ms`: local condition-poll where
/// backoff growth only slows detection — see the FIS-0016 classification.
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

    let mut restore_error: Option<String> = None;
    let tampered_result = (|| {
        run_pfctl_status(&["-a", anchor.as_str(), "-F", "all"])?;
        let tampered_rules = run_pfctl(&["-a", anchor.as_str(), "-s", "rules"])?;
        Ok::<_, String>(build_macos_killswitch_assert_report(
            tampered_rules.as_str(),
        ))
    })();

    // PF-10: restore through the helper's audited render-to-load tail rather
    // than a local temp file.
    //
    // This used to write the baseline rules with `write_restore_file` — a plain
    // `fs::write` to `$TMPDIR/rustynet-macos-killswitch-<anchor>-<millis>.pf`,
    // so: a predictable name, a symlink-following write, no `O_EXCL`, no mode
    // and no ownership check — and then ran a root `pfctl -f` against that path.
    // `load_macos_pf_anchor` owns the artifact end-to-end instead: a root-owned
    // `0700` spool directory verified not to be a symlink, an `O_EXCL` create at
    // `0600` with a 128-bit `OsRng` nonce in the name, and removal afterwards.
    //
    // Scoped honestly: this subcommand runs as root from the live-lab validator,
    // not as the daemon service, and macOS `env::temp_dir()` is normally the
    // per-user `0700` `/var/folders/...`, so this was not the daemon-uid boundary
    // bypass that `fd1b50d1` closed. But `$TMPDIR` is inherited from the invoking
    // environment, the file's integrity was never established, and it is a root
    // `pfctl -f` — which is the whole shape SR-020 asked to be converted.
    let restore_result =
        crate::privileged_helper::load_macos_pf_anchor(anchor.as_str(), baseline_rules.as_str());
    if let Err(err) = restore_result {
        restore_error = Some(err);
    }

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
#[cfg(test)]
mod tests {
    use super::*;

    /// PF-10: the anchor restore must go through the helper's audited
    /// render-to-load tail, never through a local temp file.
    ///
    /// A source pin because the real behaviour needs root and macOS. What it
    /// guards is narrow and specific: this module used to write the baseline
    /// rules with a plain `fs::write` to a predictable `$TMPDIR` name and then
    /// run a root `pfctl -f` against that path. Re-introducing a local
    /// temp-then-load here would be a silent regression of artifact custody for a
    /// root `pfctl -f`, and no unit test of the pure functions would notice.
    #[test]
    fn anchor_restore_uses_the_audited_helper_not_a_local_temp_file() {
        let source = include_str!("macos_exit_killswitch_precedence.rs");

        assert!(
            source.contains("crate::privileged_helper::load_macos_pf_anchor("),
            "the restore must call the helper's audited render-to-load tail"
        );

        // Needles are assembled at runtime so this test's own source does not
        // match them. A literal would make the assertion permanently true (the
        // file always contains it) -- the same self-reference trap as grepping a
        // process table for your own command line.
        let deleted_writer = format!("fn write_{}", "restore_file");
        assert!(
            !source.contains(&deleted_writer),
            "the local predictable-name temp writer must stay deleted"
        );

        // No `pfctl -f` may be issued from this module at all: `-f` takes a file
        // path, so its presence means an artifact whose custody this module owns
        // rather than the helper.
        let load_flag = format!("{}f\"", "\"-");
        for (index, line) in source.lines().enumerate() {
            let is_comment = line.trim_start().starts_with("//");
            let is_this_assertion = line.contains("load_flag");
            assert!(
                is_comment || is_this_assertion || !line.contains(&load_flag),
                "line {} issues a pfctl -f from this module; artifact custody for a root \
                 pfctl load belongs to the helper: {line}",
                index + 1
            );
        }
    }

    #[test]
    fn killswitch_assert_accepts_reviewed_block_all_rule() {
        let report = build_macos_killswitch_assert_report(
            "pass out quick inet on utun9 all keep state\nblock drop out quick all\n",
        );
        assert!(report.overall_ok);
        assert_eq!(report.exit_code, 0);
    }

    /// PF-05, the defect itself: a `quick` pass ABOVE the block.
    ///
    /// pf evaluates top to bottom and `quick` takes effect immediately, so each
    /// of these rulesets lets all egress out while `block drop out quick all` is
    /// still literally present. The old substring search found that text and
    /// reported the killswitch verified.
    #[test]
    fn quick_pass_above_the_block_is_not_containment() {
        // The real one. `macos_exit_nat.rs` emits exactly this line when
        // allow_egress_interface is set -- a one-boolean, full-IPv4
        // killswitch off-switch (PF-01) that this assertion used to pass.
        const EGRESS_INTERFACE_WIDE_OPEN: &str =
            "pass out quick on en0 inet all keep state\nblock drop out quick all\n";
        const UNRESTRICTED: &str = "pass out quick all\nblock drop out quick all\n";
        const ANY_TO_ANY: &str =
            "pass out quick inet from any to any keep state\nblock drop out quick all\n";
        // route-to forces egress out a named interface, bypassing routing.
        const ROUTE_TO: &str = "pass out quick route-to (en1 192.0.2.1) inet all keep state\n\
             block drop out quick all\n";
        // An interface LIST containing the physical NIC must not be credited
        // just because a tunnel appears in it.
        const INTERFACE_LIST: &str =
            "pass out quick on { utun9 en0 } all keep state\nblock drop out quick all\n";

        for (label, rules) in [
            (
                "an interface-wide pass on the physical NIC",
                EGRESS_INTERFACE_WIDE_OPEN,
            ),
            ("an unrestricted quick pass", UNRESTRICTED),
            ("an any-to-any quick pass", ANY_TO_ANY),
            ("a route-to bypass", ROUTE_TO),
            (
                "an interface list including the physical NIC",
                INTERFACE_LIST,
            ),
        ] {
            let report = build_macos_killswitch_assert_report(rules);
            assert!(
                !report.overall_ok,
                "{label} defeats the block, so the killswitch must NOT verify"
            );
            assert_eq!(report.exit_code, 2);
            assert!(
                report.reason.contains("quick"),
                "the reason must explain the precedence failure, got: {}",
                report.reason
            );
        }
    }

    /// The inverse: rulesets that genuinely contain egress must still verify, or
    /// the check fires on every working deployment and gets deleted.
    #[test]
    fn precedence_check_does_not_false_fail_real_pf_rulesets() {
        // Tunnel-scoped pass: how encrypted traffic legitimately leaves.
        const TUNNEL: &str =
            "pass out quick inet on utun9 all keep state\nblock drop out quick all\n";
        // A pass WITHOUT `quick` loses to the terminator, which has it -- pf's
        // last-match-wins never applies once a quick rule matches. Reporting
        // this would be a false positive.
        const NON_QUICK_PASS: &str = "pass out inet all keep state\nblock drop out quick all\n";
        // The blind_exit shape: quick pass on the PHYSICAL interface, but
        // bounded to the mesh CIDR as source.
        const MESH_SOURCE_BOUNDED: &str = "pass out quick on en0 inet from 100.64.0.0/10 to any keep state\n\
             block drop out quick all\n";
        // The WireGuard handshake must reach the peer endpoint before any
        // tunnel exists; a specific port bounds it.
        const ENDPOINT_ALLOW: &str = "pass out quick inet proto udp from any to any port = 51820 keep state\n\
             block drop out quick all\n";
        // Ingress rules cannot leak egress.
        const INBOUND: &str =
            "pass in quick on en0 inet all keep state\nblock drop out quick all\n";
        // Non-filter statements and comments.
        const NOISE: &str = "# generated by rustynet\nscrub-anchor \"com.apple/*\"\n\
             nat-anchor \"com.apple/*\"\nblock drop out quick all\n";

        for (label, rules) in [
            ("a tunnel-scoped quick pass", TUNNEL),
            ("a non-quick pass", NON_QUICK_PASS),
            ("a mesh-CIDR-bounded pass", MESH_SOURCE_BOUNDED),
            ("a WireGuard endpoint allow", ENDPOINT_ALLOW),
            ("an inbound pass", INBOUND),
            ("comments and anchors", NOISE),
        ] {
            let report = build_macos_killswitch_assert_report(rules);
            assert!(
                report.overall_ok,
                "{label} must still verify; got: {}",
                report.reason
            );
        }
    }

    /// Rules BELOW the terminator are unreachable: the block carries `quick`.
    #[test]
    fn quick_pass_below_the_block_is_unreachable() {
        let report = build_macos_killswitch_assert_report(
            "block drop out quick all\npass out quick on en0 all keep state\n",
        );
        assert!(
            report.overall_ok,
            "a pass beneath a quick block never evaluates; got: {}",
            report.reason
        );
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
