#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_policy::{
    AccessRequest, MembershipDirectory, MembershipStatus, PolicyRule, PolicySet, Protocol,
};

// AQ-29: the ACL/policy engine's selector parser, driven through the public
// evaluation entry points (crates/rustynet-policy/src/lib.rs:163
// PolicySet::evaluate, :184 evaluate_with_membership, which reach the
// deliberately-strict private selector parser at :749 and the CIDR parser at
// :778-799).
//
// ATTACKER: policy rules and access requests are strings that arrive from the
// control plane and from peer-supplied requests; the selector grammar is
// security-load-bearing (POL-01: an unrecognised selector must deny, not
// allow). The fuzz input is split on the first '\n' into a rule selector and
// a request selector, each of which is used BOTH as a rule side and as a
// request side, so parser, matcher, and membership-gate paths all see
// hostile strings. No pre-validation: results are ignored.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (a, b) = match text.split_once('\n') {
        Some((a, b)) => (a, b),
        None => (text.as_ref(), text.as_ref()),
    };

    let mut rules = PolicySet::default();
    rules.rules.push(PolicyRule {
        src: a.to_owned(),
        dst: b.to_owned(),
        protocol: Protocol::Any,
        action: rustynet_policy::RuleAction::Allow,
    });

    let request = AccessRequest {
        src: b.to_owned(),
        dst: a.to_owned(),
        protocol: Protocol::Tcp,
    };

    let _ = rules.evaluate(&request);

    let mut membership = MembershipDirectory::default();
    membership.set_node_status("n1", MembershipStatus::Active);
    membership.set_selector_members("tag:fuzz", ["n1"]);
    let _ = rules.evaluate_with_membership(&request, &membership);
});
