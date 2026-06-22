#![allow(clippy::result_large_err)]

//! Adversarial self-audit of the privileged-helper argv allowlist.
//!
//! Companion of the orchestrator-side `evaluate_privileged_helper_allowlist_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired through the CLI as
//! `rustynetd privileged-helper-allowlist-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §7 requires the privileged-helper / system
//! integration path to use argv-only invocation with strict input validation
//! (the daemon's only root-boundary crossing). The enforcement point is
//! [`crate::privileged_helper::validate_request`], an exact-match allowlist
//! with default-deny: anything outside the reviewed schema is rejected.
//!
//! This audit drives that REAL shipped validator with a built-in adversarial
//! corpus and asserts the contract holds on the deployed binary, per OS:
//!   - every MALICIOUS request (path traversal, anchor escape, injection
//!     metacharacters, arbitrary sysctl keys/values, non-owned nft tables,
//!     `kill` of pid 1 / non-`-TERM` signals, oversized/empty argv, an
//!     unknown program) MUST be DENIED, and
//!   - every reviewed BENIGN request MUST still be ALLOWED (so the audit is
//!     not the trivial "deny everything" pass that would also reject the real
//!     control plane).
//!
//! It runs the in-binary validator only — no privileged side effects — so it
//! is safe to run on any guest via the public CLI surface and FAILs LOUD
//! (non-zero exit) the moment the allowlist regresses in either direction.

use serde::{Deserialize, Serialize};

use crate::privileged_helper::{PrivilegedCommandProgram, validate_request};

pub const PRIVILEGED_HELPER_ALLOWLIST_AUDIT_SCHEMA_VERSION: u32 = 1;

/// Whether a corpus case is expected to be accepted or rejected by the
/// allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// A reviewed, in-policy request the allowlist MUST accept.
    Allow,
    /// An out-of-policy / adversarial request the allowlist MUST reject.
    Deny,
}

impl Expectation {
    fn as_str(self) -> &'static str {
        match self {
            Expectation::Allow => "allow",
            Expectation::Deny => "deny",
        }
    }
}

/// One adversarial-or-benign probe against the allowlist.
#[derive(Debug, Clone, Copy)]
pub struct AllowlistAuditCase {
    pub label: &'static str,
    pub program: &'static str,
    pub args: &'static [&'static str],
    pub expectation: Expectation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistAuditCaseResult {
    pub label: String,
    pub program: String,
    pub expectation: String,
    pub actual_allowed: bool,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    pub malicious_denied: u32,
    pub benign_allowed: u32,
    /// Cases whose actual outcome did not match the expectation. Empty when
    /// `overall_ok` is true. A violation is either an adversarial request the
    /// allowlist ACCEPTED (privilege-escalation regression) or a reviewed
    /// request it REJECTED (control-plane breakage).
    pub violations: Vec<AllowlistAuditCaseResult>,
}

/// Evaluate one case against the REAL allowlist validator. A program string
/// that the helper does not recognise is treated as denied (the helper would
/// never dispatch it).
pub fn evaluate_case(case: &AllowlistAuditCase) -> AllowlistAuditCaseResult {
    let (actual_allowed, detail) = match PrivilegedCommandProgram::parse(case.program) {
        None => (
            false,
            format!("program {:?} is not allowlisted", case.program),
        ),
        Some(program) => match validate_request(program, case.args) {
            Ok(()) => (true, "validate_request accepted the request".to_owned()),
            Err(reason) => (false, reason),
        },
    };
    let passed = match case.expectation {
        Expectation::Allow => actual_allowed,
        Expectation::Deny => !actual_allowed,
    };
    AllowlistAuditCaseResult {
        label: case.label.to_owned(),
        program: case.program.to_owned(),
        expectation: case.expectation.as_str().to_owned(),
        actual_allowed,
        passed,
        detail,
    }
}

/// The adversarial-plus-benign corpus. MALICIOUS cases must be denied; BENIGN
/// cases must be allowed. Every entry maps to a vulnerability-class probe from
/// the live-lab security coverage matrix (privilege escalation / helper abuse).
pub fn allowlist_audit_corpus() -> Vec<AllowlistAuditCase> {
    use Expectation::{Allow, Deny};
    vec![
        // ── MALICIOUS: must be DENIED ──────────────────────────────────────
        AllowlistAuditCase {
            label: "nft_list_non_owned_table",
            program: "nft",
            args: &["list", "table", "inet", "filter"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "nft_delete_arbitrary_table",
            program: "nft",
            args: &["delete", "table", "ip", "nat"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "nft_table_name_injection_metachars",
            program: "nft",
            args: &["list", "table", "inet", "rustynet_g1; drop"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "nft_family_spoof",
            program: "nft",
            args: &["list", "table", "bridge", "rustynet_g1"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "sysctl_arbitrary_key_core_pattern",
            program: "sysctl",
            args: &["-w", "kernel.core_pattern=|/tmp/pwn"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "sysctl_out_of_range_forward_value",
            program: "sysctl",
            args: &["-w", "net.ipv4.ip_forward=2"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "pfctl_path_traversal_load",
            program: "pfctl",
            args: &[
                "-a",
                "com.rustynet/nat",
                "-f",
                "/etc/rustynet/../../etc/shadow",
            ],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "pfctl_anchor_name_escape",
            program: "pfctl",
            args: &["-a", "com.evil/takeover", "-F", "all"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "pfctl_anchor_dotdot_segment",
            program: "pfctl",
            args: &["-a", "com.apple/rustynet_g1/../../root", "-F", "all"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "kill_pid_one",
            program: "kill",
            args: &["-TERM", "1"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "kill_non_term_signal",
            program: "kill",
            args: &["-KILL", "4321"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "wg_interface_shell_injection",
            program: "wg",
            args: &["show", "wg0; rm -rf /", "latest-handshakes"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "ip_unknown_schema",
            program: "ip",
            args: &["link", "delete", "wg0"],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "empty_argv",
            program: "nft",
            args: &[],
            expectation: Deny,
        },
        AllowlistAuditCase {
            label: "unknown_program_bash",
            program: "bash",
            args: &["-c", "id"],
            expectation: Deny,
        },
        // ── BENIGN: must be ALLOWED ────────────────────────────────────────
        AllowlistAuditCase {
            label: "nft_list_tables",
            program: "nft",
            args: &["list", "tables"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "nft_list_owned_killswitch_table",
            program: "nft",
            args: &["list", "table", "inet", "rustynet_g1"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "nft_add_owned_table",
            program: "nft",
            args: &["add", "table", "inet", "rustynet_g1"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "sysctl_enable_ipv4_forward",
            program: "sysctl",
            args: &["-w", "net.ipv4.ip_forward=1"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "sysctl_disable_ipv6",
            program: "sysctl",
            args: &["-w", "net.ipv6.conf.all.disable_ipv6=1"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "pfctl_show_info",
            program: "pfctl",
            args: &["-s", "info"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "pfctl_show_owned_anchor_nat",
            program: "pfctl",
            args: &["-a", "com.rustynet/nat", "-s", "nat"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "kill_term_normal_pid",
            program: "kill",
            args: &["-TERM", "4321"],
            expectation: Allow,
        },
        AllowlistAuditCase {
            label: "wg_version",
            program: "wg",
            args: &["--version"],
            expectation: Allow,
        },
    ]
}

/// Run the full corpus against the real allowlist and build the report.
pub fn run_privileged_helper_allowlist_audit() -> AllowlistAuditReport {
    build_allowlist_audit_report(&allowlist_audit_corpus())
}

pub fn build_allowlist_audit_report(corpus: &[AllowlistAuditCase]) -> AllowlistAuditReport {
    let results: Vec<AllowlistAuditCaseResult> = corpus.iter().map(evaluate_case).collect();
    let malicious_denied = results
        .iter()
        .zip(corpus.iter())
        .filter(|(res, case)| case.expectation == Expectation::Deny && res.passed)
        .count() as u32;
    let benign_allowed = results
        .iter()
        .zip(corpus.iter())
        .filter(|(res, case)| case.expectation == Expectation::Allow && res.passed)
        .count() as u32;
    let violations: Vec<AllowlistAuditCaseResult> =
        results.iter().filter(|res| !res.passed).cloned().collect();
    AllowlistAuditReport {
        schema_version: PRIVILEGED_HELPER_ALLOWLIST_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: corpus.len() as u32,
        malicious_denied,
        benign_allowed,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_is_substantial_and_balanced() {
        let corpus = allowlist_audit_corpus();
        let malicious = corpus
            .iter()
            .filter(|c| c.expectation == Expectation::Deny)
            .count();
        let benign = corpus
            .iter()
            .filter(|c| c.expectation == Expectation::Allow)
            .count();
        assert!(
            malicious >= 12,
            "expected a broad adversarial corpus, got {malicious}"
        );
        assert!(benign >= 6, "expected reviewed benign cases, got {benign}");
    }

    #[test]
    fn audit_passes_against_the_real_validator() {
        // This is the load-bearing check: every corpus entry's categorisation
        // is validated against the SHIPPED `validate_request`. If any
        // adversarial case is accepted or any benign case is rejected, this
        // fails — which is exactly what the live stage asserts per OS.
        let report = run_privileged_helper_allowlist_audit();
        assert!(
            report.overall_ok,
            "allowlist audit found violations: {:?}",
            report.violations
        );
        assert_eq!(
            report.total_cases,
            report.malicious_denied + report.benign_allowed
        );
    }

    #[test]
    fn audit_bites_when_an_adversarial_case_is_accepted() {
        // Prove the audit FAILS if the allowlist regressed to accept a request
        // we label Deny: mislabel a known-allowed request as Deny and confirm
        // the evaluator flags it as a violation.
        let mislabeled = AllowlistAuditCase {
            label: "regression_probe",
            program: "nft",
            args: &["list", "tables"],
            expectation: Expectation::Deny,
        };
        let result = evaluate_case(&mislabeled);
        assert!(result.actual_allowed, "nft list tables is allowlisted");
        assert!(
            !result.passed,
            "a Deny-expected case that is accepted must be flagged as a violation"
        );
        let report = build_allowlist_audit_report(&[mislabeled]);
        assert!(!report.overall_ok);
        assert_eq!(report.violations.len(), 1);
    }

    #[test]
    fn audit_bites_when_a_benign_case_is_rejected() {
        // The inverse regression: a reviewed request the allowlist refuses.
        let mislabeled = AllowlistAuditCase {
            label: "control_plane_probe",
            program: "nft",
            args: &["list", "table", "inet", "filter"],
            expectation: Expectation::Allow,
        };
        let result = evaluate_case(&mislabeled);
        assert!(!result.actual_allowed, "non-owned table is denied");
        assert!(
            !result.passed,
            "an Allow-expected case that is denied must be flagged as a violation"
        );
    }

    #[test]
    fn unknown_program_is_denied() {
        let result = evaluate_case(&AllowlistAuditCase {
            label: "x",
            program: "bash",
            args: &["-c", "id"],
            expectation: Expectation::Deny,
        });
        assert!(!result.actual_allowed);
        assert!(result.passed);
        assert!(result.detail.contains("not allowlisted"));
    }
}
