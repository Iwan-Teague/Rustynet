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

/// True only where security-audit validation runs live today (Linux). macOS /
/// Windows nodes are reported-skipped — named on disk, never a silent pass —
/// until their audit surfaces are proven, mirroring `relay_validation`'s posture
/// gate. (macOS/Windows have their own dedicated security-validator stages in
/// the bash-arm path today; folding those into the Rust engine is later work.)
pub fn security_audit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Run the eight Linux daemon self-audits through the shell seam, applying each
/// audit's typed evaluator. Returns `Err` with the first failing audit's detail
/// (fail-closed) or `Ok(())` when all eight pass — where "pass" means the
/// evaluator's full contract (`overall_ok` AND the anti-vacuity guards: no empty
/// corpus, no vacuous/reject-all baseline, no too-thin battery), not merely the
/// daemon's `overall_ok` flag.
pub fn validate_linux_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    for (label, subcommand, evaluate) in LINUX_SECURITY_AUDITS {
        let argv = [daemon_path, subcommand, "--no-fail-on-drift"];
        let out = shell
            .run_argv(&argv, &[], &[])
            .map_err(|err| format!("{label}: dispatch of `{subcommand}` failed: {err}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        evaluate(alias, &stdout).map_err(|detail| format!("{label} (`{subcommand}`): {detail}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(!security_audit_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!security_audit_runtime_implemented(
            VmGuestPlatform::Windows
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
