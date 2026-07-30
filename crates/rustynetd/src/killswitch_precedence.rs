//! Precedence-aware killswitch containment: does the terminator actually *fire*?
//!
//! Four verifier sites in this repository independently made the same mistake:
//! they asserted that a block rule **exists**, never that it is **reachable**.
//! Because pf and nftables are first-match-wins within a chain, a permissive
//! rule ordered earlier defeats a block that is still literally present — so a
//! ruleset that leaks freely passes an assertion whose text reads like proof of
//! containment. That is the whole reason the underlying permissive-rule defects
//! were *silent*: the verifiers designed to catch them credited them as passes.
//!
//! This module is the shared answer. It models a chain as an **ordered list of
//! rules** and asks the only question that matters: for the traffic class under
//! test, does any rule reach a permissive verdict before the terminator does?
//!
//! # Why the core is transport-agnostic
//!
//! pf and nftables have completely different syntax but identical *precedence
//! semantics*, and Windows WFP has the same failure mode expressed through
//! filter weights. Only the per-rule classification differs between them. So
//! the precedence walk lives here once, and each backend supplies a `classify`
//! closure that reduces one of its own rule lines to a
//! [`RuleDisposition`]. Four sites, one precedence model, one set of
//! adversarial tests — a fix here cannot regress on one platform while holding
//! on another, which is exactly how this class of defect propagated to three
//! backends in the first place.
//!
//! # Fail-closed by construction
//!
//! [`RuleDisposition::Escapes`] is the default for anything a classifier does
//! not positively recognise as safe. An unparseable, novel, or ambiguous rule
//! therefore *withholds* the containment verdict rather than being skipped. A
//! verifier that skips what it does not understand is precisely a verifier that
//! certifies the leak it was written to detect, so "unknown" must mean "not
//! proven contained" — never "harmless".
//!
//! ```
//! use rustynetd::killswitch_precedence::{
//!     terminator_is_reachable, RuleDisposition,
//! };
//!
//! // A tunnel-scoped accept cannot leak: traffic it matches leaves via the
//! // encrypted interface, so the terminator still contains everything else.
//! let contained = terminator_is_reachable(
//!     &[r#"oifname "rustynet0" accept"#, "policy drop;"],
//!     |rule| {
//!         if rule.contains("policy drop") {
//!             RuleDisposition::Terminator
//!         } else if rule.contains("rustynet0") {
//!             RuleDisposition::Contained
//!         } else {
//!             RuleDisposition::Escapes
//!         }
//!     },
//! );
//! assert!(contained.is_ok());
//! ```

/// What one rule does to the traffic class being tested for containment.
///
/// The classifier reduces a backend-specific rule line to one of these. The
/// variants are deliberately about *effect on the traffic under test*, not
/// about the rule's syntax, so the same four cases describe a pf rule, an nft
/// rule, and a WFP filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDisposition {
    /// Cannot match the traffic class at all, so its verdict is irrelevant to
    /// this containment question. An IPv4-only selector when testing IPv6
    /// containment is the canonical case: it is unreachable *for this traffic*,
    /// whatever it permits for other traffic.
    Irrelevant,
    /// Matches and permits, but the permitted path is inside the tunnel (or
    /// loopback) — so traffic it accepts is not an escape. This is the variant
    /// that keeps a real killswitch from being reported as broken: every
    /// working killswitch necessarily accepts its own tunnel egress.
    Contained,
    /// Matches and permits egress outside the tunnel, but only for a single
    /// operator-declared service or source range — a specific proto+port, or a
    /// restricted source/destination — rather than for traffic in general.
    ///
    /// This variant exists because real killswitches need such rules: the
    /// WireGuard handshake must reach the peer endpoint on the physical
    /// interface before any tunnel exists, and an exit node must forward its
    /// mesh CIDR. Treating those as escapes would report every working
    /// deployment as broken, and a check that fires on correct configuration
    /// gets deleted rather than heeded.
    ///
    /// The honest limit: such a rule *is* a real egress channel for the narrow
    /// class it names. It does not defeat containment of the general traffic
    /// class, which is what this walk decides, but auditing whether each narrow
    /// allow is itself justified is a separate question this model does not
    /// answer.
    NarrowAllow,
    /// Matches and permits egress outside the tunnel. This rule defeats the
    /// terminator for any traffic it matches. Also the fail-closed default for
    /// anything the classifier cannot positively prove safe.
    Escapes,
    /// The terminator itself — the drop/reject/block whose reachability is the
    /// question. The walk stops here: rules after it cannot un-drop traffic.
    Terminator,
}

/// A permissive rule that renders the terminator unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecedenceViolation {
    /// Zero-based index of the offending rule within the list as supplied.
    pub index: usize,
    /// The offending rule text, trimmed. Rule text is operator/OS-authored
    /// firewall syntax, never key material, so it is safe to surface.
    pub rule: String,
}

impl std::fmt::Display for PrecedenceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rule {} permits egress before the terminator is reached: {}",
            self.index, self.rule
        )
    }
}

/// The terminator was never found in the rule list at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingTerminator;

impl std::fmt::Display for MissingTerminator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no terminator (drop/reject/block) rule present")
    }
}

/// Why containment could not be proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentFailure {
    /// A permissive rule precedes the terminator.
    Escaped(PrecedenceViolation),
    /// There is no terminator to reach.
    NoTerminator(MissingTerminator),
}

impl std::fmt::Display for ContainmentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escaped(violation) => violation.fmt(f),
            Self::NoTerminator(missing) => missing.fmt(f),
        }
    }
}

/// Walk `rules` in evaluation order and decide whether the terminator is
/// reachable for the traffic class `classify` describes.
///
/// Returns `Ok(())` only when a [`RuleDisposition::Terminator`] is reached with
/// no [`RuleDisposition::Escapes`] rule before it. An empty rule list, or one
/// with no terminator, is a failure — absence of a block is never containment.
///
/// # Ordering is the caller's contract
///
/// `rules` must be in **evaluation** order, which is not always textual order.
/// nftables prints a chain's `policy` on the chain-declaration line, above the
/// rules, yet the policy is the *default* and applies only after every rule has
/// failed to match — so for a `policy drop` chain the terminator is
/// semantically last and every printed rule precedes it. A caller that passes
/// nft output verbatim, policy line included, would conclude the walk at rule
/// zero and credit containment while ignoring every accept beneath it. That is
/// the exact shape of the original defect, so callers must normalise order
/// before calling; [`nft_chain_rules_in_evaluation_order`] does it for nft.
pub fn terminator_is_reachable<S: AsRef<str>>(
    rules: &[S],
    classify: impl Fn(&str) -> RuleDisposition,
) -> Result<(), ContainmentFailure> {
    for (index, raw) in rules.iter().enumerate() {
        let rule = raw.as_ref().trim();
        if rule.is_empty() {
            continue;
        }
        match classify(rule) {
            RuleDisposition::Irrelevant
            | RuleDisposition::Contained
            | RuleDisposition::NarrowAllow => continue,
            RuleDisposition::Escapes => {
                return Err(ContainmentFailure::Escaped(PrecedenceViolation {
                    index,
                    rule: rule.to_owned(),
                }));
            }
            RuleDisposition::Terminator => return Ok(()),
        }
    }
    Err(ContainmentFailure::NoTerminator(MissingTerminator))
}

/// Reorder one nftables chain's printed lines into evaluation order.
///
/// `nft list ruleset` prints `type filter hook output priority 0; policy drop;`
/// as part of the chain declaration — textually *first*, semantically *last*.
/// This moves a `policy <verdict>` to the end and drops the non-rule chain
/// metadata, so [`terminator_is_reachable`] walks what the kernel actually
/// evaluates.
///
/// Lines are returned borrowed and trimmed. Comments and braces are dropped;
/// `counter`/`comment`-only lines are kept, because a classifier must be the
/// one to decide they are [`RuleDisposition::Irrelevant`] rather than having
/// them silently removed here.
pub fn nft_chain_rules_in_evaluation_order(chain_body: &str) -> Vec<&str> {
    let mut rules = Vec::new();
    let mut policy = None;
    for raw in chain_body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line == "}" || line == "{" {
            continue;
        }
        // The chain declaration carries `type ... hook ... priority N;` and
        // optionally `policy <verdict>;`. Split the policy out; discard the
        // rest, which declares the chain rather than filtering a packet.
        if line.starts_with("type ") || line.starts_with("chain ") || line.starts_with("table ") {
            if let Some(at) = line.find("policy ") {
                policy = Some(line[at..].trim_end_matches('}').trim());
            }
            continue;
        }
        if line.starts_with("policy ") {
            policy = Some(line);
            continue;
        }
        rules.push(line);
    }
    // Semantically last: the chain default fires only if no rule matched.
    if let Some(policy) = policy {
        rules.push(policy);
    }
    rules
}

/// Interfaces whose accepted egress is contained rather than leaked.
///
/// An accept scoped to the tunnel is the one permissive rule every functioning
/// killswitch must have — it is how encrypted traffic gets out — so it must not
/// be read as an escape. Loopback is likewise not an egress path off the host.
#[derive(Debug, Clone)]
pub struct ContainedInterfaces {
    names: Vec<String>,
}

impl Default for ContainedInterfaces {
    /// Loopback plus this project's tunnel-name families.
    ///
    /// Prefix families (`rustynet*`, `wg*`, `utun*`, `tun*`) are matched rather
    /// than exact names because the tunnel's index varies per host and the
    /// verifier sites do not all know the live device name. This is a
    /// deliberately *narrow* widening: a name outside these families is treated
    /// as an escape, so the failure direction on an unrecognised interface is
    /// "report not-contained", not "credit containment".
    fn default() -> Self {
        Self {
            names: ["lo", "rustynet", "wg", "utun", "tun"]
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }
}

impl ContainedInterfaces {
    /// Build from explicit interface names — preferred when the caller knows
    /// the live tunnel device, since it removes the prefix-family guess.
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Add an interface whose accepted traffic is contained.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.names.push(name.into());
        self
    }

    /// Whether `candidate` is a contained (non-leaking) egress interface.
    pub fn contains(&self, candidate: &str) -> bool {
        let candidate = candidate.trim().trim_matches('"');
        self.names.iter().any(|name| {
            candidate == name.as_str()
                // Prefix family: `rustynet0`, `wg0`, `utun3`. Require the
                // remainder to be digits so `wg` never matches `wgadmin-eth`.
                || (candidate.starts_with(name.as_str())
                    && !candidate[name.len()..].is_empty()
                    && candidate[name.len()..].chars().all(|c| c.is_ascii_digit()))
        })
    }

    /// Extract the `oifname`/`oif` argument of an nft rule, if any.
    pub fn nft_rule_output_interface(rule: &str) -> Option<&str> {
        for key in ["oifname ", "oif "] {
            if let Some(at) = rule.find(key) {
                let rest = rule[at + key.len()..].trim_start();
                let name = if let Some(stripped) = rest.strip_prefix('"') {
                    stripped.split('"').next()?
                } else {
                    rest.split_whitespace().next()?
                };
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this module exists to make impossible: a permissive rule
    /// ordered before the block, with the block still literally present.
    #[test]
    fn an_accept_before_the_terminator_defeats_containment() {
        let failure = terminator_is_reachable(&["accept", "drop"], |rule| {
            if rule == "drop" {
                RuleDisposition::Terminator
            } else {
                RuleDisposition::Escapes
            }
        })
        .expect_err("an unconditional accept before the drop must defeat containment");
        match failure {
            ContainmentFailure::Escaped(violation) => {
                assert_eq!(violation.index, 0);
                assert_eq!(violation.rule, "accept");
            }
            other => panic!("expected an escape, got {other:?}"),
        }
    }

    /// The inverse must hold too, or the check is useless: a real killswitch
    /// accepts its own tunnel egress and must still be credited.
    #[test]
    fn tunnel_and_irrelevant_rules_do_not_defeat_containment() {
        terminator_is_reachable(
            &[
                r#"oifname "rustynet0" accept"#,
                "ip saddr 10.0.0.0/8 accept",
                "policy drop;",
            ],
            |rule| {
                if rule.contains("policy drop") {
                    RuleDisposition::Terminator
                } else if rule.contains("ip saddr") {
                    RuleDisposition::Irrelevant
                } else if rule.contains("rustynet0") {
                    RuleDisposition::Contained
                } else {
                    RuleDisposition::Escapes
                }
            },
        )
        .expect("a tunnel-scoped accept plus an IPv4-only rule must stay contained");
    }

    /// Absence of a block is not containment. An empty chain used to be an
    /// easy false pass for a presence check that found nothing to object to.
    #[test]
    fn no_terminator_is_not_containment() {
        for rules in [vec![], vec![""], vec!["counter"], vec!["  ", "# comment"]] {
            let failure = terminator_is_reachable(&rules, |_| RuleDisposition::Irrelevant)
                .expect_err("a chain with no terminator must not be credited as contained");
            assert_eq!(
                failure,
                ContainmentFailure::NoTerminator(MissingTerminator),
                "rules {rules:?} have no terminator"
            );
        }
    }

    /// Rules after the terminator cannot un-drop traffic, so the walk must
    /// stop. Reporting them would produce false failures on real rulesets.
    #[test]
    fn rules_after_the_terminator_are_not_reached() {
        terminator_is_reachable(&["drop", "accept"], |rule| {
            if rule == "drop" {
                RuleDisposition::Terminator
            } else {
                RuleDisposition::Escapes
            }
        })
        .expect("an accept below the terminator is unreachable and must not fail the check");
    }

    /// nft prints the chain policy above the rules but applies it below them.
    /// A verifier that trusts textual order concludes at the policy line and
    /// never sees the accept — the original bug, in one assertion.
    #[test]
    fn nft_policy_is_reordered_to_last() {
        let chain = r#"chain killswitch {
    type filter hook output priority 0; policy drop;
    oifname "enp0s1" accept
}"#;
        let rules = nft_chain_rules_in_evaluation_order(chain);
        assert_eq!(rules, vec![r#"oifname "enp0s1" accept"#, "policy drop;"]);

        // And with the order corrected, the escape is now visible.
        let failure = terminator_is_reachable(&rules, |rule| {
            if rule.contains("policy drop") {
                RuleDisposition::Terminator
            } else {
                RuleDisposition::Escapes
            }
        })
        .expect_err("the accept precedes the policy and must be reported");
        assert!(matches!(failure, ContainmentFailure::Escaped(_)));
    }

    #[test]
    fn nft_reordering_handles_a_policy_on_its_own_line_and_no_policy_at_all() {
        let own_line = "chain c {\n    policy drop;\n    accept\n}";
        assert_eq!(
            nft_chain_rules_in_evaluation_order(own_line),
            vec!["accept", "policy drop;"]
        );

        let no_policy = "chain c {\n    type filter hook output priority 0;\n    drop\n}";
        assert_eq!(nft_chain_rules_in_evaluation_order(no_policy), vec!["drop"]);
    }

    #[test]
    fn contained_interfaces_match_tunnel_families_but_not_lookalikes() {
        let contained = ContainedInterfaces::default();
        for tunnel in ["lo", "rustynet0", "rustynet1", "wg0", "utun3", "tun0"] {
            assert!(contained.contains(tunnel), "{tunnel} must be contained");
        }
        for leaky in [
            "eth0",
            "enp0s1",
            "en0",
            "wlan0",
            // Lookalikes: a name that merely starts with a tunnel family but
            // is not one. Crediting these would reopen the hole via naming.
            "wgadmin-eth",
            "rustynet-bridge",
            "tunnelbroker",
            "lo-bridge",
        ] {
            assert!(!contained.contains(leaky), "{leaky} must NOT be contained");
        }
    }

    #[test]
    fn contained_interfaces_accept_an_explicit_device_name() {
        let contained = ContainedInterfaces::from_names(["nebula7"]);
        assert!(contained.contains("nebula7"));
        assert!(!contained.contains("rustynet0"));
        assert!(
            ContainedInterfaces::default()
                .with_name("nebula7")
                .contains("nebula7")
        );
    }

    #[test]
    fn nft_output_interface_is_extracted_from_both_spellings() {
        assert_eq!(
            ContainedInterfaces::nft_rule_output_interface(r#"oifname "rustynet0" accept"#),
            Some("rustynet0")
        );
        assert_eq!(
            ContainedInterfaces::nft_rule_output_interface("oif eth0 accept"),
            Some("eth0")
        );
        assert_eq!(
            ContainedInterfaces::nft_rule_output_interface("ip saddr 10.0.0.1 accept"),
            None
        );
    }
}
