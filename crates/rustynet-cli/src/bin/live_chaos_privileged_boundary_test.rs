#![forbid(unsafe_code)]

//! Live-lab chaos stage: privileged-boundary adversarial sweep.
//!
//! Converts the former `chaos_privileged_boundary` scaffold into a real proof of
//! SecurityMinimumBar §4 ("Preserve privileged-boundary hardening: argv-only exec
//! for helpers, strict input validation, no shell construction with untrusted
//! values").
//!
//! It drives the *real* privileged-helper request validator
//! ([`rustynetd::privileged_helper::validate_request`], the exact allowlist check
//! the helper runs in production at its request funnel before any binary is
//! resolved or a subprocess is spawned) with a battery of adversarial argv and
//! asserts every one is rejected fail-closed. Because `validate_request` (and the
//! `PrivilegedCommandProgram::parse` allowlist that precedes it) are pure checks
//! that run *before* `resolve_binary`/exec, the sweep performs no privileged
//! action and mutates no host state — it is rejection-only by construction.
//!
//! Scope honesty: this slice fully exercises the `malformed_argv` portion of the
//! category. The `socket_race` and `setuid_binary_inspection` slices require a
//! live helper socket / deployed-binary inspection on a guest; they are recorded
//! transparently as `skipped` (future increments) and are never claimed as
//! passed.

mod live_chaos_support;

use std::fs;
use std::path::Path;

use live_chaos_support::{ChaosConfig, ChaosStage, parse_config, unix_now};
use rustynetd::privileged_helper::{PrivilegedCommandProgram, validate_request};
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_privileged_boundary";
const ARGV_STAGE: &str = "chaos_privileged_helper_malformed_argv";

/// A single adversarial privileged-helper request that MUST be rejected.
struct AdversarialCase {
    id: &'static str,
    program: String,
    args: Vec<String>,
    /// Lowercased substring that must appear in the rejection reason, so we
    /// assert the *right* control rejected (not an unrelated error).
    expect_reason_contains: &'static str,
    rationale: &'static str,
}

fn case(
    id: &'static str,
    program: &str,
    args: &[&str],
    expect_reason_contains: &'static str,
    rationale: &'static str,
) -> AdversarialCase {
    AdversarialCase {
        id,
        program: program.to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        expect_reason_contains,
        rationale,
    }
}

/// The adversarial battery. Each case maps to a specific enforcement point in
/// `rustynetd::privileged_helper`. The `expect_reason_contains` substrings are
/// the stable rejection messages emitted by those enforcement points.
fn adversarial_cases() -> Vec<AdversarialCase> {
    let mut cases = vec![
        // --- non-allowlisted programs: rejected at PrivilegedCommandProgram::parse ---
        case(
            "unknown_program_reboot",
            "reboot",
            &["now"],
            "unsupported privileged command program",
            "a non-allowlisted program must never resolve to a helper command",
        ),
        case(
            "unknown_program_shell",
            "sh",
            &["-c", "reboot"],
            "unsupported privileged command program",
            "a shell interpreter is not an allowlisted helper program",
        ),
        case(
            "program_token_metachar",
            "ip; reboot",
            &["link"],
            "unsupported privileged command program",
            "a program string carrying shell metacharacters is not the exact allowlisted token",
        ),
        // --- global argv bounds: rejected before per-program parsing ---
        case(
            "empty_arg_element",
            "ip",
            &[""],
            "empty argument",
            "an empty argv element is rejected up front",
        ),
        // --- per-program schema: malformed but well-sized argv ---
        case(
            "ip_iface_metachar",
            "ip",
            &["link", "set", "up", "dev", "eth0; reboot"],
            "unsupported ip",
            "an interface name with shell metacharacters fails the device-name allowlist",
        ),
        case(
            "ip_iface_too_long",
            "ip",
            &["link", "set", "up", "dev", "abcdefghijklmnop"],
            "unsupported ip",
            "a 16-char interface name exceeds the 15-char device-name bound",
        ),
        case(
            "wg_path_traversal",
            "wg",
            &["set", "wg0", "private-key", "../../etc/shadow"],
            "unsupported wg",
            "a path token containing `..` (traversal) is rejected",
        ),
        case(
            "wg_relative_path",
            "wg",
            &["set", "wg0", "private-key", "relative/key"],
            "unsupported wg",
            "a non-absolute path token is rejected",
        ),
        case(
            "kill_wrong_signal",
            "kill",
            &["-KILL", "1234"],
            "unsupported kill",
            "only `-TERM` is accepted; an arbitrary signal is rejected",
        ),
        case(
            "kill_pid_one",
            "kill",
            &["-TERM", "1"],
            "unsupported kill",
            "signalling PID 1 (init) is rejected",
        ),
        case(
            "sysctl_arbitrary_key",
            "sysctl",
            &["-w", "kernel.core_pattern=|/tmp/evil"],
            "unsupported sysctl",
            "only the reviewed ip_forward/disable_ipv6 toggles are accepted",
        ),
        case(
            "nft_foreign_table",
            "nft",
            &["add", "rule", "inet", "evil_table", "killswitch", "drop"],
            "unsupported nft",
            "an nft rule targeting a non-rustynet-owned table is rejected",
        ),
    ];

    // Cases that need large owned argv built at runtime.
    cases.push(AdversarialCase {
        id: "empty_args_list",
        program: "ip".to_owned(),
        args: Vec::new(),
        expect_reason_contains: "missing arguments",
        rationale: "an empty argv list is rejected (default-deny)",
    });
    cases.push(AdversarialCase {
        id: "oversize_arg",
        program: "ip".to_owned(),
        // MAX_ARG_BYTES is 256; 300 bytes is over the bound.
        args: vec!["A".repeat(300)],
        expect_reason_contains: "argument too long",
        rationale: "an argument beyond the per-argument byte bound is rejected",
    });
    cases.push(AdversarialCase {
        id: "too_many_args",
        program: "ip".to_owned(),
        // MAX_ARGS is 128; 130 elements is over the bound.
        args: vec!["x".to_owned(); 130],
        expect_reason_contains: "too many arguments",
        rationale: "an argv list beyond the argument-count bound is rejected",
    });

    cases
}

/// Outcome of evaluating one adversarial case against the real validator.
struct CaseOutcome {
    id: &'static str,
    program: String,
    rejected: bool,
    reason: String,
    expected_reason_contains: &'static str,
    reason_matches: bool,
    rationale: &'static str,
    passed: bool,
}

/// Evaluate a case through the production rejection path: program allowlist
/// (`parse`) then argument validation (`validate_request`). Never resolves a
/// binary or execs, so an (unexpected) accept still performs no privileged work.
fn evaluate(case: &AdversarialCase) -> CaseOutcome {
    let arg_refs: Vec<&str> = case.args.iter().map(String::as_str).collect();
    let (rejected, reason) = match PrivilegedCommandProgram::parse(&case.program) {
        None => (
            true,
            format!("unsupported privileged command program: {}", case.program),
        ),
        Some(program) => match validate_request(program, &arg_refs) {
            Ok(()) => (
                false,
                "ACCEPTED: validator did not reject an adversarial request".to_owned(),
            ),
            Err(err) => (true, err),
        },
    };
    let reason_matches = reason
        .to_lowercase()
        .contains(&case.expect_reason_contains.to_lowercase());
    let passed = rejected && reason_matches;
    CaseOutcome {
        id: case.id,
        program: case.program.clone(),
        rejected,
        reason,
        expected_reason_contains: case.expect_reason_contains,
        reason_matches,
        rationale: case.rationale,
        passed,
    }
}

fn main() {
    let stages = category_stages();
    let parsed = parse_config(CATEGORY, stages, std::env::args().skip(1)).and_then(run);
    if let Err(err) = parsed {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// The three named slices of this category. Only the first is exercised here;
/// the other two are recorded `skipped` until a live-socket increment lands.
fn category_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: ARGV_STAGE,
            fault: "send helper requests with non-allowlisted programs, metacharacters, path traversal, and out-of-bound argv",
            pass_criterion: "every adversarial request is rejected fail-closed before any binary is resolved or executed",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_privileged_helper_socket_race",
            fault: "rapidly open and close helper socket during daemon startup",
            pass_criterion: "mid-create connections are rejected cleanly",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_setuid_binary_inspection",
            fault: "inspect privileged binary mode bits and privilege-dropping posture",
            pass_criterion: "no unexpected setuid surface exists",
            recovery_deadline_secs: 60,
        },
    ]
}

fn run(config: ChaosConfig) -> Result<(), String> {
    let cases = adversarial_cases();
    let outcomes: Vec<CaseOutcome> = cases.iter().map(evaluate).collect();
    let argv_passed = outcomes.iter().all(|outcome| outcome.passed);
    let accepted_count = outcomes.iter().filter(|outcome| !outcome.rejected).count();

    write_log(&config, &outcomes)?;

    let report = render_report(&config, &outcomes, argv_passed, accepted_count);
    write_parent(&config.report_path)?;
    fs::write(
        &config.report_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise privileged-boundary chaos report failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", config.report_path.display()))?;

    if argv_passed {
        Ok(())
    } else {
        Err(format!(
            "privileged-boundary adversarial sweep failed: {} of {} cases not rejected as expected ({} accepted)",
            outcomes.iter().filter(|outcome| !outcome.passed).count(),
            outcomes.len(),
            accepted_count,
        ))
    }
}

fn write_log(config: &ChaosConfig, outcomes: &[CaseOutcome]) -> Result<(), String> {
    write_parent(&config.log_path)?;
    let mut body = format!(
        "category={CATEGORY}\nstage={ARGV_STAGE}\ndry_run={}\ngenerated_at_unix={}\ncase_count={}\n",
        config.dry_run,
        unix_now(),
        outcomes.len(),
    );
    for outcome in outcomes {
        body.push_str(&format!(
            "case={} program={} rejected={} reason_matches={} passed={} reason={}\n",
            outcome.id,
            outcome.program,
            outcome.rejected,
            outcome.reason_matches,
            outcome.passed,
            outcome.reason,
        ));
    }
    fs::write(&config.log_path, body)
        .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))
}

fn render_report(
    config: &ChaosConfig,
    outcomes: &[CaseOutcome],
    argv_passed: bool,
    accepted_count: usize,
) -> Value {
    let case_values: Vec<Value> = outcomes
        .iter()
        .map(|outcome| {
            json!({
                "case": outcome.id,
                "program": outcome.program,
                "rejected": outcome.rejected,
                "expected_reason_contains": outcome.expected_reason_contains,
                "reason_matches": outcome.reason_matches,
                "reason": outcome.reason,
                "rationale": outcome.rationale,
                "status": if outcome.passed { "pass" } else { "fail" },
            })
        })
        .collect();

    let argv_stage = config.stages.iter().find(|stage| stage.name == ARGV_STAGE);

    let mut stage_values = vec![json!({
        "name": ARGV_STAGE,
        "status": if argv_passed { "pass" } else { "fail" },
        "fault": argv_stage.map(|stage| stage.fault),
        "pass_criterion": argv_stage.map(|stage| stage.pass_criterion),
        "recovery_deadline_secs": argv_stage.map(|stage| stage.recovery_deadline_secs),
        "measured_recovery_secs": 0,
        "plaintext_leak_check": "not-applicable-offline",
        "production_state_mutation": false,
        "expected_result": "reject_fail_closed",
        "case_count": outcomes.len(),
        "cases": case_values,
    })];
    // Slices not yet exercised by this offline argv increment — recorded honestly.
    for stage in config
        .stages
        .iter()
        .filter(|stage| stage.name != ARGV_STAGE)
    {
        stage_values.push(json!({
            "name": stage.name,
            "status": "skipped",
            "fault": stage.fault,
            "pass_criterion": stage.pass_criterion,
            "recovery_deadline_secs": stage.recovery_deadline_secs,
            "skip_reason": "requires a live helper socket / deployed-binary inspection on a guest; not exercised by the offline argv-validation slice",
        }));
    }

    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": if argv_passed { "pass" } else { "fail" },
        "summary": "argv-only privileged-helper boundary rejects adversarial requests fail-closed; socket-race and setuid-inspection slices not yet exercised",
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "stages": stage_values,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": false,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "offline_only": true,
            "production_accepted": false,
            "expected_result": "reject_fail_closed",
            "argv_only_boundary_rejects_adversarial_input": argv_passed,
            "no_adversarial_request_accepted": accepted_count == 0
        }
    })
}

fn write_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_adversarial_case_is_rejected_with_expected_reason() {
        for case in adversarial_cases() {
            let outcome = evaluate(&case);
            assert!(
                outcome.rejected,
                "case `{}` was ACCEPTED by the privileged-helper validator (program={}, reason={})",
                case.id, outcome.program, outcome.reason
            );
            assert!(
                outcome.reason_matches,
                "case `{}` rejected but reason did not contain `{}` (reason={})",
                case.id, case.expect_reason_contains, outcome.reason
            );
            assert!(outcome.passed, "case `{}` did not pass", case.id);
        }
    }

    #[test]
    fn no_adversarial_case_is_accepted() {
        let accepted: Vec<&'static str> = adversarial_cases()
            .iter()
            .filter(|case| !evaluate(case).rejected)
            .map(|case| case.id)
            .collect();
        assert!(
            accepted.is_empty(),
            "adversarial cases unexpectedly accepted: {accepted:?}"
        );
    }

    #[test]
    fn allowlist_recognises_valid_programs_so_rejections_are_meaningful() {
        // Guard against a validator that simply rejects everything: the program
        // allowlist must still recognise legitimate helper programs.
        assert!(PrivilegedCommandProgram::parse("ip").is_some());
        assert!(PrivilegedCommandProgram::parse("nft").is_some());
        assert!(PrivilegedCommandProgram::parse("wg").is_some());
        assert!(PrivilegedCommandProgram::parse("reboot").is_none());
    }

    #[test]
    fn sweep_covers_program_parse_and_global_and_per_program_paths() {
        let ids: Vec<&'static str> = adversarial_cases().iter().map(|case| case.id).collect();
        // program-allowlist rejection
        assert!(ids.contains(&"unknown_program_reboot"));
        // global argv bounds
        assert!(ids.contains(&"empty_args_list"));
        assert!(ids.contains(&"oversize_arg"));
        assert!(ids.contains(&"too_many_args"));
        // per-program schema
        assert!(ids.contains(&"wg_path_traversal"));
        assert!(ids.contains(&"kill_pid_one"));
    }
}
