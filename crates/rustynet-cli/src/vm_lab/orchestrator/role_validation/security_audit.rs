#![allow(dead_code)]
//! Cross-OS security-audit validation for the standard orchestrator.
//!
//! Folds the eight Tier-0 Linux adversarial daemon self-audits into a standard
//! [`OrchestrationStage`](crate::vm_lab::orchestrator::stage::OrchestrationStage)
//! so the Rust `--node` engine proves them, not just the bash live suite. Each
//! audit runs `rustynetd <check>-audit --no-fail-on-drift` over the hardened
//! [`RemoteShellHost`] seam and is accepted ONLY by the SAME typed evaluator the
//! bash live-suite applies (`evaluate_*` in `vm_lab`), which fails closed on an
//! empty corpus, a vacuous (reject-all / no-baseline) result, a too-thin
//! adversarial battery, or any `overall_ok`/`violations` inconsistency — so a
//! broken, stripped, or vacuous audit fails the stage rather than silently
//! passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// Signature every Tier-0 audit evaluator shares:
/// `(node_alias, raw_json) -> Ok(summary) | Err(reason)`. These evaluators are
/// the SAME pure functions the bash live-suite applies (in `vm_lab`), so both
/// engines enforce byte-identical acceptance criteria.
type AuditEvaluator = fn(&str, &str) -> Result<String, String>;

/// The eight Tier-0 daemon self-audit subcommands `rustynetd` actually exposes
/// (see the dispatch table in `crates/rustynetd/src/main.rs`), as
/// `(matrix-friendly label, daemon subcommand, typed evaluator)`. The labels
/// mirror the `linux_*` run-matrix security columns.
///
/// NOTE — subcommand names are ground-truthed against the daemon dispatch, not
/// the column labels: the signature battery is `membership-signature-audit`
/// (the column is `..._signature_forgery`), and `hello_limiter_flood` is NOT a
/// daemon self-audit — it is proven by a separate live flood test, so this
/// stage carries `blind-exit-reversal-audit` (a real daemon audit with its own
/// `linux_blind_exit_reversal_denied` column) as the eighth instead.
///
/// DEPTH PARITY: the evaluator is the SAME pure function the bash live-suite
/// uses (`crate::vm_lab::evaluate_*`), so the Rust `--node` engine now enforces
/// the FULL depth — beyond the daemon's own `overall_ok`, each rejects an empty
/// corpus, a vacuous (reject-all / no-baseline) result, a too-thin adversarial
/// battery, and any `overall_ok`/`violations` inconsistency. A stripped or
/// vacuous audit therefore fails the stage instead of trivially passing.
pub const LINUX_SECURITY_AUDITS: &[(&str, &str, AuditEvaluator)] = &[
    (
        "membership_revoke_applies",
        "membership-revoke-audit",
        crate::vm_lab::evaluate_membership_revoke_audit_report,
    ),
    (
        "revoked_peer_denied_e2e",
        "revoked-peer-denied-audit",
        crate::vm_lab::evaluate_revoked_peer_denied_report,
    ),
    (
        "membership_signature_forgery",
        "membership-signature-audit",
        crate::vm_lab::evaluate_membership_signature_audit_report,
    ),
    (
        "privileged_helper_allowlist",
        "privileged-helper-allowlist-audit",
        crate::vm_lab::evaluate_privileged_helper_allowlist_report,
    ),
    (
        "policy_default_deny",
        "policy-default-deny-audit",
        crate::vm_lab::evaluate_policy_default_deny_report,
    ),
    (
        "gossip_revoked_readmit",
        "gossip-revoked-readmit-audit",
        crate::vm_lab::evaluate_gossip_revoked_readmit_report,
    ),
    (
        "enrollment_replay",
        "enrollment-replay-audit",
        crate::vm_lab::evaluate_enrollment_replay_report,
    ),
    (
        "blind_exit_reversal_denied",
        "blind-exit-reversal-audit",
        crate::vm_lab::evaluate_blind_exit_reversal_report,
    ),
];

/// True on every desktop platform: the audits dispatch through the adapter's
/// [`RemoteShellHost`] seam, which Linux, macOS and Windows all implement.
///
/// Do not read this as "live-proven on all three". It is a *runtime-support*
/// gate, not an evidence claim: as of 2026-08-10 only Linux has ever executed
/// this stage in a recorded `--node` run, because no macOS or Windows node has
/// been present in one. A non-desktop platform (iOS/Android) has no daemon audit
/// surface and is reported-skipped — named on disk, never a silent pass.
pub fn security_audit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// The verdict for ONE Tier-0 audit on ONE node.
///
/// `Blocked` is deliberately distinct from `Failed`: it means the control was
/// never exercised (the daemon subcommand could not be dispatched at all), which
/// is not the same evidentiary claim as "the control was exercised and the
/// daemon violated it". Both fail the stage; only `Failed` asserts a violation.
/// Collapsing the two would let an unreachable host read as eight security
/// failures, or — worse, in the other direction — let an unexercised control
/// inherit a neighbouring control's pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    Passed,
    Failed(String),
    Blocked(String),
}

impl AuditVerdict {
    /// The run-matrix status string this verdict records. `blocked` outranks
    /// both `skip` and `pass` in the recorder's precedence (see `status_rank`),
    /// so an unexercised control can never let a platform read green.
    pub fn matrix_status(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "pass",
            AuditVerdict::Failed(_) => "fail",
            AuditVerdict::Blocked(_) => "blocked",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            AuditVerdict::Passed => None,
            AuditVerdict::Failed(detail) | AuditVerdict::Blocked(detail) => Some(detail.as_str()),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, AuditVerdict::Passed)
    }
}

/// One audit's outcome on one node, in the shape the per-control artifact and
/// the run-matrix recorder both consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditResult {
    /// The matrix-friendly label — byte-identical to the `{platform}_{label}`
    /// run-matrix column suffix.
    pub audit_id: &'static str,
    pub verdict: AuditVerdict,
}

/// Run all eight daemon self-audits through the shell seam, applying each
/// audit's typed evaluator, and return a verdict for EVERY audit.
///
/// "Pass" means the evaluator's full contract (`overall_ok` AND the anti-vacuity
/// guards: no empty corpus, no vacuous/reject-all baseline, no too-thin battery),
/// not merely the daemon's `overall_ok` flag.
///
/// RUN-ALL, NOT FAIL-FAST — a deliberate change from the earlier fail-fast loop,
/// and the reason it is safe: fail-closed is a property of the STAGE outcome,
/// which [`security_audits_ok`] still derives from "did every audit pass". It was
/// never a property of the loop. Stopping at the first failure left the other
/// seven controls with no verdict at all, and the run matrix then recorded them
/// as `not_run` — a column value that asserts "no node of this platform was in
/// the run", which is false and materially misleading on a run where the node was
/// present and the control simply was not reached.
pub fn run_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Vec<AuditResult> {
    LINUX_SECURITY_AUDITS
        .iter()
        .map(|(label, subcommand, evaluate)| {
            let argv = [daemon_path, *subcommand, "--no-fail-on-drift"];
            let verdict = match shell.run_argv(&argv, &[], &[]) {
                Err(err) => AuditVerdict::Blocked(format!(
                    "{label}: dispatch of `{subcommand}` failed: {err}"
                )),
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    match evaluate(alias, &stdout) {
                        Ok(_) => AuditVerdict::Passed,
                        Err(detail) => {
                            AuditVerdict::Failed(format!("{label} (`{subcommand}`): {detail}"))
                        }
                    }
                }
            };
            AuditResult {
                audit_id: label,
                verdict,
            }
        })
        .collect()
}

/// Fail-closed reduction of a node's audit results to the stage's verdict:
/// `Err` with every non-passing audit's detail if ANY audit did not pass.
pub fn security_audits_ok(results: &[AuditResult]) -> Result<(), String> {
    let problems: Vec<String> = results
        .iter()
        .filter_map(|result| result.verdict.detail().map(str::to_owned))
        .collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Back-compatible wrapper: run every audit and reduce to the fail-closed
/// stage verdict, discarding the per-control detail.
pub fn validate_linux_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    security_audits_ok(&run_security_audits(shell, daemon_path, alias))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_macos_and_windows() {
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Macos));
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Windows));
        assert!(!security_audit_runtime_implemented(VmGuestPlatform::Ios));
        assert!(!security_audit_runtime_implemented(
            VmGuestPlatform::Android
        ));
    }

    #[test]
    fn covers_all_eight_tier0_audits() {
        let labels: Vec<&str> = LINUX_SECURITY_AUDITS.iter().map(|(l, _, _)| *l).collect();
        assert_eq!(labels.len(), 8);
        for expected in [
            "membership_revoke_applies",
            "revoked_peer_denied_e2e",
            "membership_signature_forgery",
            "privileged_helper_allowlist",
            "policy_default_deny",
            "gossip_revoked_readmit",
            "enrollment_replay",
            "blind_exit_reversal_denied",
        ] {
            assert!(labels.contains(&expected), "missing audit: {expected}");
        }
        // Every subcommand is a distinct `*-audit` that the daemon dispatch in
        // rustynetd/src/main.rs actually exposes.
        let daemon_subcommands = [
            "membership-revoke-audit",
            "revoked-peer-denied-audit",
            "membership-signature-audit",
            "privileged-helper-allowlist-audit",
            "policy-default-deny-audit",
            "gossip-revoked-readmit-audit",
            "enrollment-replay-audit",
            "blind-exit-reversal-audit",
        ];
        for (_, sub, _) in LINUX_SECURITY_AUDITS {
            assert!(sub.ends_with("-audit"), "not an audit subcommand: {sub}");
            assert!(
                daemon_subcommands.contains(sub),
                "subcommand not in the rustynetd dispatch table: {sub}"
            );
        }
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn audit_argv(subcommand: &str) -> [&str; 3] {
        // Mirrors the argv `validate_linux_security_audits` dispatches.
        [TEST_DAEMON, subcommand, "--no-fail-on-drift"]
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn validate_fails_closed_when_first_audit_report_is_invalid() {
        // Program the FIRST audit (membership-revoke) with a structurally
        // invalid report. Its typed evaluator must reject it, and the loop must
        // return that failure prefixed with the matrix label — proving the
        // dispatch calls the right evaluator and fails closed (not the old
        // overall_ok-only acceptance).
        let mock = MockShellHost::new();
        let argv = audit_argv("membership-revoke-audit");
        mock.program_run_response(&argv, exit_ok(r#"{"schema_version": 999}"#));
        let err = validate_linux_security_audits(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid audit report must fail the stage");
        assert!(
            err.contains("membership_revoke_applies"),
            "error must name the failing audit: {err}"
        );
        assert!(
            err.contains("membership-revoke-audit"),
            "error must name the subcommand: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        // No programmed response and no default → the shell seam errors on the
        // first audit; that must surface as a fail-closed dispatch error, never
        // a pass.
        let mock = MockShellHost::new();
        let err = validate_linux_security_audits(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of `membership-revoke-audit` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }

    #[test]
    fn every_audit_gets_a_verdict_even_when_the_first_one_fails() {
        // The regression this pins: the loop used to stop at the first failure,
        // so seven controls got no verdict at all and the run matrix recorded
        // them as `not_run` — a value that asserts no node of that platform was
        // in the run. Here the node IS in the run and every control must be
        // accounted for.
        let mock = MockShellHost::new();
        let results = run_security_audits(&mock, TEST_DAEMON, "deb-1");
        assert_eq!(
            results.len(),
            LINUX_SECURITY_AUDITS.len(),
            "every audit must produce a verdict, not just the ones before the first failure"
        );
        for (result, (label, _, _)) in results.iter().zip(LINUX_SECURITY_AUDITS) {
            assert_eq!(result.audit_id, *label, "verdicts must stay in audit order");
            assert!(
                matches!(result.verdict, AuditVerdict::Blocked(_)),
                "an undispatchable audit is BLOCKED (not exercised), never failed or passed: {:?}",
                result.verdict
            );
        }
        // Fail-closed is preserved at the stage level regardless.
        assert!(security_audits_ok(&results).is_err());
    }

    #[test]
    fn a_blocked_audit_is_never_reported_as_a_pass() {
        let results = vec![
            AuditResult {
                audit_id: "policy_default_deny",
                verdict: AuditVerdict::Passed,
            },
            AuditResult {
                audit_id: "enrollment_replay",
                verdict: AuditVerdict::Blocked("dispatch failed".into()),
            },
        ];
        assert_eq!(results[0].verdict.matrix_status(), "pass");
        assert_eq!(results[1].verdict.matrix_status(), "blocked");
        assert!(security_audits_ok(&results).is_err());
    }

    #[test]
    fn validate_rejects_vacuous_signature_audit_via_typed_evaluator() {
        // Prove the depth-parity win directly: a membership-signature report the
        // daemon calls overall_ok=true but which is VACUOUS (no valid baseline
        // accepted) must still fail. The old overall_ok-only check would have
        // passed it; the typed evaluator this stage now dispatches to does not.
        let vacuous = serde_json::json!({
            "schema_version": 1,
            "total_cases": 12,
            "baseline_accepted": 0,
            "forgeries_rejected": 12,
            "overall_ok": true,
            "violations": []
        })
        .to_string();
        let err = crate::vm_lab::evaluate_membership_signature_audit_report("deb-1", &vacuous)
            .expect_err("a no-baseline (vacuous) signature audit must be rejected");
        assert!(err.contains("vacuous"), "{err}");
    }
}
