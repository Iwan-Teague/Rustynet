#![allow(clippy::result_large_err)]

//! Adversarial self-audit of the default-deny ACL evaluator.
//!
//! Companion of the orchestrator-side `evaluate_policy_default_deny_report` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd policy-default-deny-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.6 + `CLAUDE.md` §10.4: default-deny is mandatory
//! across ACL/routes. The evaluator must start from deny-all and only allow on
//! an explicit present match; empty/unmatched/protocol-mismatched input denies,
//! and a REVOKED identity is denied by the membership-aware path even when a
//! stale allow rule names it.
//!
//! This audit drives the REAL [`rustynet_policy::PolicySet::evaluate`] and
//! [`rustynet_policy::PolicySet::evaluate_with_membership`] with a truth-table
//! corpus, in-process (no VM, no state), and asserts each case's decision
//! matches expectation — including at least one ALLOW case so the audit is not
//! the vacuous "deny everything" pass. It FAILs LOUD the moment the deployed
//! evaluator's default-deny posture regresses, per OS.
//!
//! NOTE: this audit verifies the evaluator's own truth table. The separate
//! finding DD-03/RSA-0007/0008 — that the dataplane/exit/LAN admission paths
//! call the membership-BLIND `evaluate` rather than `evaluate_with_membership`
//! — is a wiring defect at the call sites, not in the evaluator; it is tracked
//! in the coverage doc and is out of scope for this evaluator-level audit.

use serde::{Deserialize, Serialize};

use rustynet_policy::{
    AccessRequest, Decision, MembershipDirectory, MembershipStatus, PolicyRule, PolicySet,
    Protocol, RuleAction,
};

pub const POLICY_DEFAULT_DENY_AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evaluator {
    /// Membership-blind `PolicySet::evaluate`.
    Blind,
    /// Membership-aware `PolicySet::evaluate_with_membership`.
    WithMembership,
}

struct DefaultDenyCase {
    id: &'static str,
    rules: Vec<PolicyRule>,
    /// `(node_id, status)` entries to register in the membership directory.
    membership: Vec<(&'static str, MembershipStatus)>,
    request: AccessRequest,
    evaluator: Evaluator,
    expected: Decision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultDenyCaseResult {
    pub id: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDefaultDenyAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    pub allow_cases_passed: u32,
    pub deny_cases_passed: u32,
    /// Cases whose decision did not match expectation. Empty when overall_ok.
    pub violations: Vec<DefaultDenyCaseResult>,
}

fn rule(src: &str, dst: &str, protocol: Protocol, action: RuleAction) -> PolicyRule {
    PolicyRule {
        src: src.to_owned(),
        dst: dst.to_owned(),
        protocol,
        action,
    }
}

fn request(src: &str, dst: &str, protocol: Protocol) -> AccessRequest {
    AccessRequest {
        src: src.to_owned(),
        dst: dst.to_owned(),
        protocol,
    }
}

fn decision_str(decision: Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_owned(),
        Decision::Deny => "deny".to_owned(),
    }
}

fn corpus() -> Vec<DefaultDenyCase> {
    use Decision::{Allow, Deny};
    use Evaluator::{Blind, WithMembership};
    use MembershipStatus::{Active, Revoked};
    use Protocol::{Any, Tcp, Udp};
    use RuleAction::{Allow as RAllow, Deny as RDeny};

    vec![
        // Empty policy denies (the core default-deny invariant), both paths.
        DefaultDenyCase {
            id: "empty_policy_denies_blind",
            rules: vec![],
            membership: vec![],
            request: request("node:a", "tag:servers", Tcp),
            evaluator: Blind,
            expected: Deny,
        },
        DefaultDenyCase {
            id: "empty_policy_denies_with_membership",
            // Membership is keyed by the BARE node id; `node:` selectors are
            // stripped to the id before the status lookup.
            rules: vec![],
            membership: vec![("a", Active), ("s", Active)],
            request: request("node:a", "node:s", Tcp),
            evaluator: WithMembership,
            expected: Deny,
        },
        // Anti-vacuous: an explicit allow does grant (the audit is not deny-all).
        DefaultDenyCase {
            id: "explicit_wildcard_allow_grants",
            rules: vec![rule("*", "*", Any, RAllow)],
            membership: vec![],
            request: request("node:a", "node:b", Tcp),
            evaluator: Blind,
            expected: Allow,
        },
        // An unmatched request falls through to deny-all.
        DefaultDenyCase {
            id: "unmatched_request_denied",
            rules: vec![rule("node:x", "node:y", Any, RAllow)],
            membership: vec![],
            request: request("node:a", "node:b", Tcp),
            evaluator: Blind,
            expected: Deny,
        },
        // First-match-wins: a deny rule preceding a wildcard allow denies.
        DefaultDenyCase {
            id: "explicit_deny_precedes_allow",
            rules: vec![rule("node:b", "*", Any, RDeny), rule("*", "*", Any, RAllow)],
            membership: vec![],
            request: request("node:b", "node:s", Tcp),
            evaluator: Blind,
            expected: Deny,
        },
        // A protocol-scoped allow does not match a different protocol.
        DefaultDenyCase {
            id: "protocol_mismatch_denied",
            rules: vec![rule("*", "*", Tcp, RAllow)],
            membership: vec![],
            request: request("node:a", "node:b", Udp),
            evaluator: Blind,
            expected: Deny,
        },
        // Membership-aware: a REVOKED source is denied even with an allow rule.
        DefaultDenyCase {
            id: "revoked_source_denied_with_membership",
            rules: vec![rule("node:b", "node:s", Any, RAllow)],
            membership: vec![("b", Revoked), ("s", Active)],
            request: request("node:b", "node:s", Tcp),
            evaluator: WithMembership,
            expected: Deny,
        },
        // Membership-aware: a REVOKED destination is denied even with an allow rule.
        DefaultDenyCase {
            id: "revoked_destination_denied_with_membership",
            rules: vec![rule("node:b", "node:s", Any, RAllow)],
            membership: vec![("b", Active), ("s", Revoked)],
            request: request("node:b", "node:s", Tcp),
            evaluator: WithMembership,
            expected: Deny,
        },
        // Membership-aware: both Active + allow rule present => allow (control).
        DefaultDenyCase {
            id: "active_pair_allowed_with_membership",
            rules: vec![rule("node:b", "node:s", Any, RAllow)],
            membership: vec![("b", Active), ("s", Active)],
            request: request("node:b", "node:s", Tcp),
            evaluator: WithMembership,
            expected: Allow,
        },
    ]
}

fn evaluate_case(case: &DefaultDenyCase) -> DefaultDenyCaseResult {
    let set = PolicySet {
        rules: case.rules.clone(),
    };
    let actual = match case.evaluator {
        Evaluator::Blind => set.evaluate(&case.request),
        Evaluator::WithMembership => {
            let mut directory = MembershipDirectory::default();
            for (node_id, status) in &case.membership {
                directory.set_node_status(*node_id, *status);
            }
            set.evaluate_with_membership(&case.request, &directory)
        }
    };
    DefaultDenyCaseResult {
        id: case.id.to_owned(),
        expected: decision_str(case.expected),
        actual: decision_str(actual),
        passed: actual == case.expected,
    }
}

pub fn run_policy_default_deny_audit() -> PolicyDefaultDenyAuditReport {
    build_policy_default_deny_report(&corpus())
}

fn build_policy_default_deny_report(corpus: &[DefaultDenyCase]) -> PolicyDefaultDenyAuditReport {
    let results: Vec<DefaultDenyCaseResult> = corpus.iter().map(evaluate_case).collect();
    let allow_cases_passed = corpus
        .iter()
        .zip(results.iter())
        .filter(|(case, res)| case.expected == Decision::Allow && res.passed)
        .count() as u32;
    let deny_cases_passed = corpus
        .iter()
        .zip(results.iter())
        .filter(|(case, res)| case.expected == Decision::Deny && res.passed)
        .count() as u32;
    let violations: Vec<DefaultDenyCaseResult> =
        results.iter().filter(|res| !res.passed).cloned().collect();
    PolicyDefaultDenyAuditReport {
        schema_version: POLICY_DEFAULT_DENY_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: corpus.len() as u32,
        allow_cases_passed,
        deny_cases_passed,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_has_allow_and_deny_cases() {
        let c = corpus();
        let allows = c.iter().filter(|x| x.expected == Decision::Allow).count();
        let denies = c.iter().filter(|x| x.expected == Decision::Deny).count();
        assert!(allows >= 1, "must have an allow case (anti-vacuous)");
        assert!(
            denies >= 5,
            "expected a broad deny truth table, got {denies}"
        );
    }

    #[test]
    fn audit_passes_against_the_real_evaluator() {
        let report = run_policy_default_deny_audit();
        assert!(
            report.overall_ok,
            "default-deny audit found violations: {:?}",
            report.violations
        );
        assert!(
            report.allow_cases_passed >= 1,
            "anti-vacuous: an allow must pass"
        );
        assert!(report.deny_cases_passed >= 5);
    }

    #[test]
    fn audit_bites_when_a_deny_case_is_allowed() {
        // Mislabel an explicit-allow case as expecting Deny: the real evaluator
        // returns Allow, so the case must be flagged.
        let mislabeled = DefaultDenyCase {
            id: "bite_probe",
            rules: vec![rule("*", "*", Protocol::Any, RuleAction::Allow)],
            membership: vec![],
            request: request("node:a", "node:b", Protocol::Tcp),
            evaluator: Evaluator::Blind,
            expected: Decision::Deny,
        };
        let result = evaluate_case(&mislabeled);
        assert_eq!(result.actual, "allow");
        assert!(!result.passed);
        let report = build_policy_default_deny_report(&[mislabeled]);
        assert!(!report.overall_ok);
        assert_eq!(report.violations.len(), 1);
    }

    #[test]
    fn revoked_node_is_denied_by_membership_path() {
        // Direct confirmation of the membership-aware deny (the correct
        // behaviour the dataplane SHOULD route through — see DD-03 finding).
        let case = corpus()
            .into_iter()
            .find(|c| c.id == "revoked_source_denied_with_membership")
            .expect("case present");
        assert_eq!(evaluate_case(&case).actual, "deny");
    }
}
