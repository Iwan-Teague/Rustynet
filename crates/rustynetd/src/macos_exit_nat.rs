//! macOS PF NAT policy for the regular `exit` role.
//!
//! The regular exit NATs mesh-CIDR traffic out the physical egress interface
//! so mesh peers can reach the internet through this node. Unlike
//! [`crate::macos_blind_exit`] (which *blocks* internet egress and only relays
//! mesh traffic), the exit installs one NAT *translation* rule per mesh prefix
//! into the `com.rustynet/nat` anchor and the daemon enables IPv4 forwarding.
//! Together that is exactly the observable "exit active" state the live
//! lifecycle snapshot ([`crate::macos_exit_nat_lifecycle`]) verifies:
//! `pfctl -a com.rustynet/nat -s nat` shows at least one `nat ...` rule and
//! `sysctl -n net.inet.ip.forwarding` reads `1`.
//!
//! Scope boundary: this module owns only the *translation* anchor. The
//! filter-side posture — the killswitch `block drop out quick all` and the
//! mesh-forwarding pass — lives in the generation-numbered killswitch anchor
//! `com.apple/rustynet_g<N>` (see [`crate::macos_exit_killswitch_precedence`])
//! and is managed by the backend killswitch path, not here. Keeping NAT in its
//! own anchor mirrors `pf`'s separation of translation and filter rules and
//! lets the lifecycle teardown flush NAT without disturbing the killswitch.
//!
//! Every public entry point validates its inputs and fails closed *before* any
//! rule text is produced: an empty/malformed interface, anchor, or CIDR is an
//! error, never a default. Route-rewriting primitives (`route-to` / `reply-to`
//! / `dup-to`) are rejected by the evaluator because they would silently route
//! around the reviewed final-hop path.

use std::net::IpAddr;

use crate::macos_exit_nat_lifecycle::DEFAULT_MACOS_EXIT_PF_ANCHOR;

/// Reviewed default translation anchor for the regular exit. Re-exported from
/// the lifecycle module so the builder and the live snapshot can never drift.
pub const DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR: &str = DEFAULT_MACOS_EXIT_PF_ANCHOR;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosExitNatPfConfig {
    /// Physical egress interface the NAT translates onto (e.g. `en0`).
    pub egress_interface: String,
    /// Mesh prefixes whose traffic is NATed out the egress interface. One
    /// translation rule is emitted per prefix and the address family is
    /// derived from each prefix. Must be non-empty — default-deny: no
    /// prefixes means no exit, which is an error rather than a no-op anchor.
    pub mesh_cidrs: Vec<String>,
    /// PF translation anchor name. Defaults to `com.rustynet/nat`.
    pub anchor_name: String,
}

impl MacosExitNatPfConfig {
    /// Construct and validate a config with the reviewed default anchor name.
    pub fn new(
        egress_interface: impl Into<String>,
        mesh_cidrs: Vec<String>,
    ) -> Result<Self, String> {
        let config = Self {
            egress_interface: egress_interface.into(),
            mesh_cidrs,
            anchor_name: DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR.to_owned(),
        };
        validate_macos_exit_nat_pf_config(&config)?;
        Ok(config)
    }
}

/// Events that can prompt removal of the exit NAT anchor.
///
/// The regular exit is reversible, so — unlike `blind_exit`, whose anchor
/// persists until factory reset — the NAT anchor must be flushed on *every*
/// deactivation path. Leaving a loaded NAT anchor (and enabled forwarding)
/// after the exit capability is gone is residue, which CLAUDE.md §10.7 treats
/// as a release-blocker. Teardown therefore always runs, and always before the
/// signed capability is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosExitNatCleanupEvent {
    DaemonShutdown,
    RoleDemotion,
    CapabilityRevoked,
    FailClosedTransition,
    CrashRecovery,
}

/// The exit NAT anchor is reversible: it is removed on any deactivation event.
pub fn should_remove_macos_exit_nat_anchor(_event: MacosExitNatCleanupEvent) -> bool {
    true
}

/// True when `anchor` is the reviewed regular-exit NAT translation anchor.
pub fn is_macos_exit_nat_anchor(anchor: &str) -> bool {
    anchor == DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR
}

/// Build the `pf` NAT ruleset for the exit's translation anchor.
///
/// Emits one rule per mesh prefix:
/// `nat on <egress> <af> from <cidr> to any -> (<egress>)`. The egress
/// interface is wrapped in parentheses so `pf` re-resolves the translation
/// address if the interface IP changes (e.g. DHCP renew), and the address
/// family is placed after `on <iface>` because macOS `pfctl` rejects
/// `<af> on <iface>` ordering.
pub fn build_macos_exit_nat_pf_rules(config: &MacosExitNatPfConfig) -> Result<String, String> {
    validate_macos_exit_nat_pf_config(config)?;
    let mut rules = String::new();
    for cidr in &config.mesh_cidrs {
        let family = pf_family_for_cidr(cidr.as_str())?;
        rules.push_str(&format!(
            "nat on {} {} from {} to any -> ({})\n",
            config.egress_interface, family, cidr, config.egress_interface
        ));
    }
    Ok(rules)
}

/// Validate a loaded/generated NAT ruleset against the reviewed shape.
///
/// Used by the live verification path, which feeds `pfctl -a <anchor> -s nat`
/// output back in. Returns the list of drift reasons (empty == compliant).
/// `pfctl` re-renders translation rules into a canonical form (it appends a
/// `round-robin` pool keyword and may rewrite `-> (en0)` as `-> (en0)
/// round-robin`); [`normalize_pf_nat_rule`] folds those back so a correct
/// ruleset validates identically whether freshly built or round-tripped
/// through `pfctl`.
pub fn evaluate_macos_exit_nat_pf_rules(rules: &str, config: &MacosExitNatPfConfig) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Err(err) = validate_macos_exit_nat_pf_config(config) {
        reasons.push(err);
        return reasons;
    }

    // The reviewed translation anchor must contain EXACTLY the set of NAT
    // rules the builder emits for the configured mesh prefixes — one per
    // prefix, each translating onto the egress interface. Computing the
    // expected set and requiring every loaded line to be a member of it
    // enforces, in one pass: the right rules are present; no rule translates
    // onto an unreviewed interface (neither the `on <iface>` source scope nor
    // the `-> (<iface>)` target may drift); and no non-NAT filter rule
    // (`pass`/`block`/…) has been smuggled into the translation anchor.
    let mut expected: Vec<String> = Vec::new();
    for cidr in &config.mesh_cidrs {
        match pf_family_for_cidr(cidr.as_str()) {
            Ok(family) => expected.push(normalize_pf_nat_rule(&format!(
                "nat on {} {} from {} to any -> ({})",
                config.egress_interface, family, cidr, config.egress_interface
            ))),
            Err(err) => reasons.push(err),
        }
    }

    let actual: Vec<String> = rules
        .lines()
        .map(normalize_pf_nat_rule)
        .filter(|line| !line.is_empty())
        .collect();

    if actual.is_empty() {
        reasons.push("exit NAT rules missing: anchor has no `nat ...` translation rule".to_owned());
    }
    if contains_forbidden_route_primitive(&actual) {
        reasons.push(
            "exit NAT rules must not contain route-to/reply-to/dup-to bypass primitives".to_owned(),
        );
    }

    // Every expected translation must be present.
    for rule in &expected {
        if !actual.contains(rule) {
            reasons.push(format!(
                "exit NAT rules missing expected translation: {rule}"
            ));
        }
    }
    // Every loaded line must be one of the expected translations. This rejects
    // an unreviewed NAT rule (drifted source/destination/interface or
    // `-> (<iface>)` target) and any non-NAT filter rule injected into the
    // anchor.
    for line in &actual {
        if !expected.contains(line) {
            reasons.push(format!("exit NAT anchor contains unreviewed rule: {line}"));
        }
    }

    reasons
}

fn validate_macos_exit_nat_pf_config(config: &MacosExitNatPfConfig) -> Result<(), String> {
    validate_interface_name(config.egress_interface.as_str())?;
    validate_anchor_name(config.anchor_name.as_str())?;
    if config.mesh_cidrs.is_empty() {
        return Err("exit NAT requires at least one mesh CIDR (default-deny)".to_owned());
    }
    for cidr in &config.mesh_cidrs {
        // The mesh CIDR becomes the SOURCE of a `nat on <egress> from
        // <mesh_cidr> to any -> (egress)` rule. Bounding it to a
        // private/CGNAT/ULA range keeps the regular exit from masquerading
        // local-origin / non-mesh traffic if a compromised daemon supplies a
        // global/default-route source (mirrors the blind_exit egress guard).
        crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr(cidr.as_str())?;
    }
    Ok(())
}

fn validate_interface_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 31
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!("invalid PF interface name for exit NAT: {value:?}"));
    }
    Ok(())
}

fn validate_anchor_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || value.contains("..")
        || value.starts_with('/')
        || value.ends_with('/')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(format!("invalid PF anchor name for exit NAT: {value:?}"));
    }
    Ok(())
}

fn pf_family_for_cidr(value: &str) -> Result<&'static str, String> {
    let addr = value
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR for exit NAT: {value:?}"))?
        .0;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid CIDR address for exit NAT: {value:?}"))?;
    Ok(if ip.is_ipv4() { "inet" } else { "inet6" })
}

fn normalize_pf_nat_rule(line: &str) -> String {
    // Strip comments, collapse whitespace, lowercase, then fold `pfctl`'s
    // canonicalizations so a generated rule matches the same rule after it has
    // round-tripped through `pfctl -s nat`:
    //   - `pfctl` appends a `round-robin` pool keyword to `-> (iface)` rules;
    //   - an unspecified source/dest is expanded to `from any to any`.
    // Each replacement is idempotent (a no-op when the token is absent) so it
    // can only let a correct rule match, never mask a real difference.
    line.split('#')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace(") round-robin", ")")
        .replace(" from any to any ", " to any ")
}

fn contains_forbidden_route_primitive(lines: &[String]) -> bool {
    lines.iter().any(|line| {
        line.contains(" route-to ") || line.contains(" reply-to ") || line.contains(" dup-to ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MacosExitNatPfConfig {
        MacosExitNatPfConfig::new("en0", vec!["100.64.0.0/10".to_owned()]).unwrap()
    }

    #[test]
    fn anchor_and_interface_validators_enforce_allowlists() {
        // PF anchor names: bounded, path-traversal-free, controlled charset.
        assert!(validate_anchor_name("com.rustynet/nat").is_ok());
        assert!(validate_anchor_name("rustynet.exit_nat-1").is_ok());
        assert!(validate_anchor_name("").is_err());
        assert!(validate_anchor_name("../evil").is_err()); // ".." traversal
        assert!(validate_anchor_name("/abs").is_err()); // leading '/'
        assert!(validate_anchor_name("trail/").is_err()); // trailing '/'
        assert!(validate_anchor_name("has;semi").is_err()); // out-of-charset
        assert!(validate_anchor_name(&"a".repeat(97)).is_err()); // too long

        // PF interface names: bounded (<=31), controlled charset.
        assert!(validate_interface_name("en0").is_ok());
        assert!(validate_interface_name("utun9").is_ok());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("en 0").is_err()); // space
        assert!(validate_interface_name("en;0").is_err()); // ';'
        assert!(validate_interface_name(&"a".repeat(32)).is_err()); // too long
    }

    #[test]
    fn builder_emits_reviewed_nat_rule() {
        let rules = build_macos_exit_nat_pf_rules(&config()).unwrap();
        assert_eq!(
            rules,
            "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n"
        );
        assert!(evaluate_macos_exit_nat_pf_rules(&rules, &config()).is_empty());
    }

    #[test]
    fn builder_emits_one_rule_per_prefix_with_derived_family() {
        let cfg = MacosExitNatPfConfig::new(
            "en0",
            vec!["100.64.0.0/10".to_owned(), "fd7a::/48".to_owned()],
        )
        .unwrap();
        let rules = build_macos_exit_nat_pf_rules(&cfg).unwrap();
        assert!(rules.contains("nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n"));
        assert!(rules.contains("nat on en0 inet6 from fd7a::/48 to any -> (en0)\n"));
        assert!(evaluate_macos_exit_nat_pf_rules(&rules, &cfg).is_empty());
    }

    #[test]
    fn snapshot_anchor_present_sees_built_rule() {
        // The live lifecycle snapshot counts the anchor "present" when a line
        // starts with `nat`. Guard that the builder's output satisfies it.
        let rules = build_macos_exit_nat_pf_rules(&config()).unwrap();
        assert!(rules.lines().any(|l| l.trim_start().starts_with("nat ")));
    }

    #[test]
    fn evaluator_accepts_pfctl_rendered_round_robin() {
        // `pfctl -s nat` echoes the rule with a trailing `round-robin` pool
        // keyword; the live verification feeds that back in and it must still
        // validate identically to the generated form.
        let cfg = config();
        let rendered = "nat on en0 inet from 100.64.0.0/10 to any -> (en0) round-robin\n";
        let reasons = evaluate_macos_exit_nat_pf_rules(rendered, &cfg);
        assert!(reasons.is_empty(), "{reasons:?}");
    }

    #[test]
    fn evaluator_flags_missing_nat_rule() {
        let cfg = config();
        let reasons = evaluate_macos_exit_nat_pf_rules("# empty anchor\n", &cfg);
        assert!(reasons.iter().any(|r| r.contains("missing")));
    }

    #[test]
    fn evaluator_rejects_translation_on_unreviewed_interface() {
        let cfg = config();
        let rules = "nat on en1 inet from 100.64.0.0/10 to any -> (en1)\n";
        let reasons = evaluate_macos_exit_nat_pf_rules(rules, &cfg);
        // The whole rule is on the wrong interface: it is both an unreviewed
        // rule and the expected en0 rule is missing.
        assert!(reasons.iter().any(|r| r.contains("unreviewed rule")));
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("missing expected translation"))
        );
    }

    #[test]
    fn evaluator_rejects_nat_to_unreviewed_target_interface() {
        // Source/`on` interface is the reviewed egress, but the `-> (<iface>)`
        // translation target is a different interface — must be rejected (the
        // `on <iface>` token alone is not sufficient).
        let cfg = config();
        let rules = "nat on en0 inet from 100.64.0.0/10 to any -> (en1)\n";
        let reasons = evaluate_macos_exit_nat_pf_rules(rules, &cfg);
        assert!(reasons.iter().any(|r| r.contains("unreviewed rule")));
    }

    #[test]
    fn evaluator_rejects_non_nat_filter_rule_in_anchor() {
        // A filter rule smuggled into the translation anchor must be flagged —
        // the NAT anchor owns only translation rules.
        let cfg = config();
        let mut rules = build_macos_exit_nat_pf_rules(&cfg).unwrap();
        rules.push_str("pass out quick on en0 inet all keep state\n");
        let reasons = evaluate_macos_exit_nat_pf_rules(&rules, &cfg);
        assert!(reasons.iter().any(|r| r.contains("unreviewed rule")));
    }

    #[test]
    fn evaluator_rejects_substring_interface_name_collision() {
        // Regression for the substring check: config egress "en" must not be
        // satisfied by a rule on "en0".
        let cfg = MacosExitNatPfConfig::new("en", vec!["100.64.0.0/10".to_owned()]).unwrap();
        let rules = "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n";
        let reasons = evaluate_macos_exit_nat_pf_rules(rules, &cfg);
        assert!(reasons.iter().any(|r| r.contains("unreviewed rule")));
    }

    #[test]
    fn evaluator_rejects_route_bypass_primitives() {
        let cfg = config();
        let mut rules = build_macos_exit_nat_pf_rules(&cfg).unwrap();
        rules.push_str("pass out quick route-to (en1 192.0.2.1) inet all keep state\n");
        let reasons = evaluate_macos_exit_nat_pf_rules(&rules, &cfg);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("route-to/reply-to/dup-to"))
        );
    }

    #[test]
    fn empty_mesh_cidrs_fail_closed() {
        let err = MacosExitNatPfConfig::new("en0", Vec::new())
            .expect_err("no mesh CIDR must fail closed");
        assert!(err.contains("at least one mesh CIDR"));
    }

    #[test]
    fn global_or_default_route_mesh_cidr_fails_closed() {
        // The mesh CIDR is the NAT source; a global/default-route source would
        // masquerade local-origin / non-mesh egress. Mirrors the blind_exit
        // egress guard (pfctl-boundary review).
        for hostile in ["0.0.0.0/0", "::/0", "8.8.8.0/24", "100.0.0.0/8"] {
            MacosExitNatPfConfig::new("en0", vec![hostile.to_owned()])
                .expect_err(&format!("{hostile} must fail closed as a NAT source"));
        }
        // A legitimate CGNAT mesh range still constructs.
        MacosExitNatPfConfig::new("en0", vec!["100.64.0.0/10".to_owned()])
            .expect("legit CGNAT mesh must be accepted");
    }

    #[test]
    fn invalid_tokens_fail_closed_before_pfctl() {
        let err = MacosExitNatPfConfig::new("en 0", vec!["100.64.0.0/10".to_owned()])
            .expect_err("space in interface must fail");
        assert!(err.contains("interface"));

        let err = MacosExitNatPfConfig::new("en0", vec!["not-a-cidr".to_owned()])
            .expect_err("malformed CIDR must fail");
        assert!(err.contains("CIDR"));

        let mut cfg = config();
        cfg.anchor_name = "com.rustynet/../escape".to_owned();
        let err = build_macos_exit_nat_pf_rules(&cfg)
            .expect_err("anchor traversal must fail before pfctl");
        assert!(err.contains("anchor"));
    }

    #[test]
    fn exit_nat_anchor_is_removed_on_every_deactivation_event() {
        for event in [
            MacosExitNatCleanupEvent::DaemonShutdown,
            MacosExitNatCleanupEvent::RoleDemotion,
            MacosExitNatCleanupEvent::CapabilityRevoked,
            MacosExitNatCleanupEvent::FailClosedTransition,
            MacosExitNatCleanupEvent::CrashRecovery,
        ] {
            assert!(
                should_remove_macos_exit_nat_anchor(event),
                "{event:?} must remove the reversible exit NAT anchor"
            );
        }
    }

    #[test]
    fn anchor_predicate_matches_default() {
        assert!(is_macos_exit_nat_anchor(DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR));
        assert!(is_macos_exit_nat_anchor("com.rustynet/nat"));
        assert!(!is_macos_exit_nat_anchor("com.rustynet/blind_exit"));
    }
}
