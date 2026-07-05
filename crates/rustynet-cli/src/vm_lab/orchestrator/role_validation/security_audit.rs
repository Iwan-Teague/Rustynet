#![allow(dead_code)]
//! Cross-OS security-audit validation for the standard orchestrator.
//!
//! Folds the eight Tier-0 Linux adversarial daemon self-audits into a standard
//! [`OrchestrationStage`](crate::vm_lab::orchestrator::stage::OrchestrationStage)
//! so the Rust `--node` engine proves them, not just the bash live suite. Each
//! audit runs `rustynetd <check>-audit --no-fail-on-drift` over the hardened
//! [`RemoteShellHost`] seam and is accepted ONLY on an explicit
//! `overall_ok: true` — [`validator_report_ok`] fails closed on absent / false /
//! unparseable output, so a broken or missing audit fails the stage rather than
//! silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh::validator_report_ok;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// The eight Tier-0 daemon self-audit subcommands `rustynetd` actually exposes
/// (see the dispatch table in `crates/rustynetd/src/main.rs`), as
/// `(matrix-friendly label, daemon subcommand)`. The labels mirror the
/// `linux_*` run-matrix security columns.
///
/// NOTE — subcommand names are ground-truthed against the daemon dispatch, not
/// the column labels: the signature battery is `membership-signature-audit`
/// (the column is `..._signature_forgery`), and `hello_limiter_flood` is NOT a
/// daemon self-audit — it is proven by a separate live flood test, so this
/// stage carries `blind-exit-reversal-audit` (a real daemon audit with its own
/// `linux_blind_exit_reversal_denied` column) as the eighth instead.
///
/// PARITY DEPTH (follow-up): the bash live-suite evaluators (see the pure
/// evaluators around `rustynetd membership-signature-audit` /
/// `membership-revoke-audit` in `vm_lab/mod.rs`) validate MORE than
/// `overall_ok` — they reject an empty corpus, a vacuous (reject-all) baseline,
/// and a too-thin adversarial battery. This stage currently accepts the
/// daemon's own `overall_ok: true` as the fail-closed minimum; folding those
/// anti-vacuity evaluators in per-audit is tracked as later Bucket-1 hardening.
pub const LINUX_SECURITY_AUDITS: &[(&str, &str)] = &[
    ("membership_revoke_applies", "membership-revoke-audit"),
    ("revoked_peer_denied_e2e", "revoked-peer-denied-audit"),
    ("membership_signature_forgery", "membership-signature-audit"),
    (
        "privileged_helper_allowlist",
        "privileged-helper-allowlist-audit",
    ),
    ("policy_default_deny", "policy-default-deny-audit"),
    ("gossip_revoked_readmit", "gossip-revoked-readmit-audit"),
    ("enrollment_replay", "enrollment-replay-audit"),
    ("blind_exit_reversal_denied", "blind-exit-reversal-audit"),
];

/// True only where security-audit validation runs live today (Linux). macOS /
/// Windows nodes are reported-skipped — named on disk, never a silent pass —
/// until their audit surfaces are proven, mirroring `relay_validation`'s posture
/// gate. (macOS/Windows have their own dedicated security-validator stages in
/// the bash-arm path today; folding those into the Rust engine is later work.)
pub fn security_audit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Run the eight Linux daemon self-audits through the shell seam. Returns `Err`
/// with the first failing audit's detail (fail-closed) or `Ok(())` when all
/// eight report `overall_ok: true`.
pub fn validate_linux_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
) -> Result<(), String> {
    for (label, subcommand) in LINUX_SECURITY_AUDITS {
        let argv = [daemon_path, subcommand, "--no-fail-on-drift"];
        let out = shell
            .run_argv(&argv, &[], &[])
            .map_err(|err| format!("{label}: dispatch of `{subcommand}` failed: {err}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !validator_report_ok(&stdout) {
            let snippet: String = stdout.trim().chars().take(400).collect();
            return Err(format!(
                "{label} (`{subcommand}`) did not report overall_ok:true (rc={}); output: {snippet}",
                out.code
            ));
        }
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
        let labels: Vec<&str> = LINUX_SECURITY_AUDITS.iter().map(|(l, _)| *l).collect();
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
        for (_, sub) in LINUX_SECURITY_AUDITS {
            assert!(sub.ends_with("-audit"), "not an audit subcommand: {sub}");
            assert!(
                daemon_subcommands.contains(sub),
                "subcommand not in the rustynetd dispatch table: {sub}"
            );
        }
    }
}
