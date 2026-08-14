//! Linux nftables policy for the `blind_exit` role.
//!
//! This is the Linux parity of [`crate::macos_blind_exit`]. The `blind_exit`
//! role is a *hardened final-hop exit* (Linux/macOS only, per
//! `NodeRoleTaxonomy_2026-05-21.md` and the dataplane execution plan): it
//! forwards mesh-sourced traffic to the internet but is locked down far
//! tighter than a regular NATing exit. The reviewed posture is:
//!
//! * **Local-origin egress is tunnel-only.** The node's own outbound traffic
//!   may leave only through the RustyNet tunnel interface — never directly out
//!   the physical egress interface. (The base killswitch `OUTPUT` chain already
//!   enforces this with `oifname <tunnel> accept` + `policy drop`; the
//!   blind_exit path must NOT add the regular-exit `oifname <egress> accept`
//!   own-egress allow.)
//! * **Mesh-exit forwarding is scoped to the signed mesh CIDR.** Forwarded
//!   traffic may cross from the tunnel to the egress interface only when its
//!   source address is inside the bounded mesh CIDR. A regular exit forwards
//!   *all* tunnel→egress traffic; blind_exit must not.
//! * **No NAT translation.** Unlike a regular exit, blind_exit installs no
//!   masquerade rule — there is no `ip rustynet_nat` table. Forwarded mesh
//!   packets keep their mesh source (the "blind" property); the node never
//!   rewrites them to its own address.
//! * **Terminal default-deny.** The `forward` chain keeps `policy drop`, so
//!   anything not explicitly allowed above is dropped.
//!
//! Like the macOS anchor, this posture is irreversible by policy: once
//! installed it is re-applied (never relaxed to an open NAT) on rollback;
//! leaving the role requires a factory reset.
//!
//! This module is `#![forbid(unsafe_code)]` and pure: it builds the nft
//! argv sequences and evaluates a captured `nft list ruleset` dump. The
//! privileged execution lives in the Linux command system; the evaluator is
//! what the runtime assert path and the unit tests both call.

#![forbid(unsafe_code)]

use crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr;

/// Reviewed configuration for the Linux blind_exit nftables posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBlindExitConfig {
    /// RustyNet tunnel interface (e.g. `rustynet0`). Local-origin egress is
    /// permitted only out this interface.
    pub tunnel_interface: String,
    /// Physical egress interface (e.g. `eth0`). Forwarded mesh traffic may
    /// leave only here, and only when sourced from `mesh_cidr`.
    pub egress_interface: String,
    /// Bounded private/CGNAT/ULA mesh CIDR. Becomes the `saddr` match of the
    /// mesh-scoped forward allow; a global/default-route range is rejected.
    pub mesh_cidr: String,
}

impl LinuxBlindExitConfig {
    pub fn new(
        tunnel_interface: impl Into<String>,
        egress_interface: impl Into<String>,
        mesh_cidr: impl Into<String>,
    ) -> Result<Self, String> {
        let config = Self {
            tunnel_interface: tunnel_interface.into(),
            egress_interface: egress_interface.into(),
            mesh_cidr: mesh_cidr.into(),
        };
        validate_linux_blind_exit_config(&config)?;
        Ok(config)
    }
}

/// The nftables layer-3 family keyword (`ip` / `ip6`) for a mesh CIDR's
/// `saddr` match. Mirrors `pf_family_for_cidr` in the macOS module.
fn nft_saddr_family_for_cidr(value: &str) -> Result<&'static str, String> {
    let addr = value
        .split_once('/')
        .ok_or_else(|| format!("invalid mesh CIDR for blind_exit: {value:?}"))?
        .0;
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid mesh CIDR address for blind_exit: {value:?}"))?;
    Ok(if ip.is_ipv4() { "ip" } else { "ip6" })
}

/// Build the nft argv sequences that (re)install the hardened blind_exit
/// `forward` chain inside `inet <table>`.
///
/// The caller (the Linux command system) supplies the live, generation-rotated
/// killswitch table name. The returned sequence:
///
/// 1. flushes the `forward` chain (clears the regular-exit unrestricted
///    `iifname <tunnel> oifname <egress> accept` rule the base killswitch
///    installs, while keeping the chain's `policy drop`),
/// 2. re-adds the conntrack established/related accept,
/// 3. adds the **mesh-source-scoped** final-hop allow only.
///
/// It deliberately emits NO masquerade rule and NO own-egress allow.
pub fn build_linux_blind_exit_forward_commands(
    config: &LinuxBlindExitConfig,
    table: &str,
) -> Result<Vec<Vec<String>>, String> {
    validate_linux_blind_exit_config(config)?;
    validate_nft_table_name(table)?;
    let saddr_family = nft_saddr_family_for_cidr(config.mesh_cidr.as_str())?;
    Ok(vec![
        vec![
            "flush".to_owned(),
            "chain".to_owned(),
            "inet".to_owned(),
            table.to_owned(),
            "forward".to_owned(),
        ],
        vec![
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.to_owned(),
            "forward".to_owned(),
            "ct".to_owned(),
            "state".to_owned(),
            "established,related".to_owned(),
            "accept".to_owned(),
        ],
        vec![
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.to_owned(),
            "forward".to_owned(),
            "iifname".to_owned(),
            config.tunnel_interface.clone(),
            "oifname".to_owned(),
            config.egress_interface.clone(),
            saddr_family.to_owned(),
            "saddr".to_owned(),
            config.mesh_cidr.clone(),
            "accept".to_owned(),
        ],
    ])
}

/// Evaluate a captured `nft list ruleset` dump against the reviewed
/// blind_exit posture. Returns the list of fail-closed reasons; an empty
/// vector means the posture is intact. Mirrors
/// `evaluate_macos_blind_exit_pf_rules`.
///
/// Enforced invariants:
/// * the mesh-source-scoped final-hop forward allow is present,
/// * there is NO unrestricted `iifname <tunnel> oifname <egress> accept`
///   forward rule (the regular-exit bypass that would forward non-mesh
///   sources),
/// * there is NO `masquerade` rule anywhere (blind_exit never NATs),
/// * there is NO regular-exit own-egress `oifname <egress> accept` allow
///   (local-origin egress stays tunnel-only).
pub fn evaluate_linux_blind_exit_ruleset(
    ruleset: &str,
    config: &LinuxBlindExitConfig,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Err(err) = validate_linux_blind_exit_config(config) {
        reasons.push(err);
        return reasons;
    }
    let saddr_family = match nft_saddr_family_for_cidr(config.mesh_cidr.as_str()) {
        Ok(value) => value,
        Err(err) => {
            reasons.push(err);
            return reasons;
        }
    };
    let normalized: Vec<String> = ruleset.lines().map(normalize_nft_rule).collect();

    // No NAT translation anywhere — blind_exit is "blind" precisely because it
    // never rewrites the mesh source.
    //
    // The scan stays HOST-WIDE on purpose. A `masquerade` installed by another
    // firewall (a firewalld zone with masquerading enabled, say) rewrites this
    // node's egress just as effectively as one of ours would, so narrowing this
    // to Rustynet's own table would convert a true positive into a fail-open on
    // exactly the hosts most likely to have one.
    //
    // What it must NOT do is confuse a conntrack MATCH with a NAT STATEMENT.
    // `ct status dnat accept` tests whether a packet's flow was translated by
    // someone; it performs no translation. Stock firewalld ships three such
    // lines in `filter_FORWARD` (measured on `fedora-utm-1`), so a bare
    // `contains(" dnat ")` made this control impossible to satisfy on any
    // firewalld host — the check failed for a reason unrelated to NAT, which is
    // a false positive on a release-blocking control. `ct status` expressions
    // are therefore removed before the NAT keywords are looked for.
    if normalized.iter().any(|line| line_performs_nat(line)) {
        reasons.push(
            "blind_exit nft ruleset must not contain NAT (masquerade/snat/dnat) rules".to_owned(),
        );
    }

    // The mesh-scoped final-hop allow must be present.
    let mesh_scoped = format!(
        "iifname {} oifname {} {} saddr {} accept",
        config.tunnel_interface, config.egress_interface, saddr_family, config.mesh_cidr
    );
    if !normalized.iter().any(|line| line == &mesh_scoped) {
        reasons.push(format!(
            "blind_exit nft ruleset missing mesh-scoped final-hop forward allow \
             (iifname {} oifname {} {} saddr {} accept)",
            config.tunnel_interface, config.egress_interface, saddr_family, config.mesh_cidr
        ));
    }

    // No unrestricted tunnel->egress forward allow (a regular exit installs
    // this; blind_exit must scope it to the mesh source).
    let unrestricted_forward = format!(
        "iifname {} oifname {} accept",
        config.tunnel_interface, config.egress_interface
    );
    if normalized.iter().any(|line| line == &unrestricted_forward) {
        reasons.push(format!(
            "blind_exit nft ruleset contains the regular-exit unrestricted \
             tunnel->egress forward allow (iifname {} oifname {} accept); \
             it must be scoped to the mesh source",
            config.tunnel_interface, config.egress_interface
        ));
    }

    // No regular-exit own-egress allow — local-origin egress stays tunnel-only.
    let own_egress = format!("oifname {} accept", config.egress_interface);
    if normalized.iter().any(|line| line == &own_egress) {
        reasons.push(format!(
            "blind_exit nft ruleset contains the regular-exit own-egress allow \
             (oifname {} accept); local-origin egress must stay tunnel-only",
            config.egress_interface
        ));
    }

    reasons
}

/// Whether the blind_exit posture survives the given cleanup event. Mirrors
/// the macOS policy: only a factory reset removes the hardened posture; every
/// other event (shutdown, key rotation, fail-closed transition, crash
/// recovery) must leave it installed because the role is irreversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBlindExitCleanupEvent {
    DaemonShutdown,
    KeyRotation,
    FailClosedTransition,
    CrashRecovery,
    FactoryReset,
}

pub fn should_remove_linux_blind_exit_posture(event: LinuxBlindExitCleanupEvent) -> bool {
    matches!(event, LinuxBlindExitCleanupEvent::FactoryReset)
}

fn validate_linux_blind_exit_config(config: &LinuxBlindExitConfig) -> Result<(), String> {
    validate_interface_name(config.tunnel_interface.as_str())?;
    validate_interface_name(config.egress_interface.as_str())?;
    if config.tunnel_interface == config.egress_interface {
        return Err("blind_exit tunnel and egress interfaces must differ".to_owned());
    }
    // The mesh CIDR becomes the SOURCE of the `iifname <tunnel> oifname
    // <egress> saddr <mesh_cidr> accept` forward rule. A global/default-route
    // source there (e.g. 0.0.0.0/0) would forward arbitrary non-mesh traffic
    // out the egress, defeating the mesh-scope lockdown — so it must be a
    // bounded private/CGNAT/ULA range, validated by the shared verifier the
    // macOS path uses too.
    validate_mesh_egress_source_cidr(config.mesh_cidr.as_str())?;
    Ok(())
}

fn validate_interface_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "invalid nft interface name for blind_exit: {value:?}"
        ));
    }
    Ok(())
}

fn validate_nft_table_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(format!("invalid nft table name for blind_exit: {value:?}"));
    }
    Ok(())
}

/// Fold an `nft list ruleset` line into the canonical token form the builder
/// emits: drop comments, strip the interface-name quotes nft renders, and
/// collapse whitespace. Each transform is idempotent so it can only make a
/// correct rule match — never mask a real difference (mirrors the macOS
/// `normalize_pf_rule` rationale).
/// Does this normalized rule line actually PERFORM NAT?
///
/// Replaces a substring scan for `"masquerade"` / `" snat "` / `" dnat "`, which
/// was wrong in both directions on a real host:
///
/// * FALSE POSITIVE — nftables uses `dnat`/`snat` as conntrack status flags as
///   well as NAT statements. `ct status dnat accept` tests whether some other
///   party translated a flow and translates nothing itself. Stock firewalld
///   ships three such lines in `filter_FORWARD` (measured on `fedora-utm-1`), so
///   the old scan made this control impossible to satisfy on ANY firewalld host,
///   failing for a reason unrelated to NAT.
/// * FALSE NEGATIVE — the space-delimited substrings never matched a keyword in
///   the FIRST token, because `normalize_nft_rule` strips indentation. An
///   unconditional `dnat to 10.0.0.1` rule therefore passed a control whose
///   entire purpose is to reject it.
///
/// A NAT statement is recognised structurally instead: `masquerade` as a bare
/// token, or `snat`/`dnat` followed by `to` (optionally via a family qualifier,
/// as in `dnat ip to 10.0.0.1`). Requiring the `to` is what keeps a chain or set
/// merely NAMED `dnat` from tripping the control.
///
/// Requiring `to` is ALSO what makes the conntrack matches safe, with no need to
/// pre-strip `ct status` expressions: in `ct status dnat accept` the flag is
/// followed by `accept`, and in `ct status { dnat, snat } accept` by a comma or
/// brace. A stripping pass was written first and then removed — mutation testing
/// showed disabling it changed no verdict, because this rule already covers
/// every spelling nft emits. If the `to` requirement is ever relaxed, that
/// analysis has to be redone.
///
/// The scan deliberately remains HOST-WIDE. A `masquerade` installed by another
/// firewall rewrites this node's egress just as effectively as one of ours, so
/// narrowing it to Rustynet's own table would convert a true positive into a
/// fail-open on exactly the hosts most likely to carry one.
fn line_performs_nat(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.contains(&"masquerade") {
        return true;
    }
    tokens.iter().enumerate().any(|(idx, token)| {
        if *token != "snat" && *token != "dnat" {
            return false;
        }
        // `dnat to <addr>` or a family-qualified `dnat ip to <addr>`.
        tokens.get(idx + 1) == Some(&"to") || tokens.get(idx + 2) == Some(&"to")
    })
}

fn normalize_nft_rule(line: &str) -> String {
    line.split('#')
        .next()
        .unwrap_or_default()
        .replace('"', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LinuxBlindExitConfig {
        LinuxBlindExitConfig::new("rustynet0", "eth0", "100.64.0.0/10").unwrap()
    }

    /// A conntrack STATUS MATCH is not a NAT statement. Stock firewalld ships
    /// three of these in `filter_FORWARD`; before this distinction existed the
    /// blind-exit control could not pass on any firewalld host, failing for a
    /// reason that had nothing to do with NAT.
    #[test]
    fn ct_status_dnat_match_is_not_treated_as_nat() {
        assert!(!line_performs_nat("ct status dnat accept"));
        assert!(!line_performs_nat("ct status snat accept"));
        assert!(!line_performs_nat("ct status { dnat, snat } accept"));
        // The real line, verbatim from a Fedora guest's ruleset.
        assert!(!line_performs_nat(&normalize_nft_rule(
            "\t\tct status dnat accept"
        )));
    }

    /// The other half of the same defect: the old space-delimited substring scan
    /// could not see a keyword in the FIRST token, because normalization strips
    /// indentation. An unconditional redirect-style rule slipped through a
    /// control whose whole purpose is to reject it.
    #[test]
    fn nat_statement_is_caught_even_as_the_leading_token() {
        assert!(line_performs_nat("dnat to 10.0.0.1"));
        assert!(line_performs_nat("snat to 192.0.2.1"));
        assert!(line_performs_nat("masquerade"));
        assert!(line_performs_nat(&normalize_nft_rule(
            "\t\tdnat to 10.0.0.1"
        )));
    }

    /// Family-qualified NAT statements and NAT sharing a line with a ct match
    /// must both still be caught.
    #[test]
    fn family_qualified_and_mixed_lines_still_count_as_nat() {
        assert!(line_performs_nat("ip daddr 1.2.3.4 dnat ip to 10.0.0.1"));
        assert!(line_performs_nat("oifname eth0 masquerade"));
        // A genuine NAT statement is not hidden by a ct status match beside it.
        assert!(line_performs_nat("ct status dnat oifname eth0 masquerade"));
    }

    /// A chain or set merely NAMED `dnat` performs no translation. Requiring the
    /// `to` keyword is what keeps this from becoming a new false positive.
    #[test]
    fn a_chain_named_dnat_is_not_a_nat_statement() {
        assert!(!line_performs_nat("chain dnat {"));
        assert!(!line_performs_nat("jump dnat"));
    }

    /// The evaluator as a whole must accept a compliant blind_exit ruleset that
    /// coexists with firewalld's conntrack matches — the end-to-end shape of the
    /// release blocker.
    #[test]
    fn compliant_ruleset_passes_alongside_firewalld_ct_status_lines() {
        let ruleset = "\
table inet firewalld {
  chain filter_FORWARD {
    ct state { established, related } accept
    ct status dnat accept
    reject with icmpx admin-prohibited
  }
}
table inet rustynet_g3 {
  chain forward {
    ct state established,related accept
    iifname \"rustynet0\" oifname \"eth0\" ip saddr 100.64.0.0/10 accept
  }
}";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            !reasons.iter().any(|r| r.contains("must not contain NAT")),
            "firewalld ct-status lines must not read as NAT: {reasons:?}"
        );
    }

    /// And a REAL foreign masquerade must still fail the control, because it
    /// rewrites this node's egress regardless of which firewall installed it.
    #[test]
    fn foreign_masquerade_still_fails_the_control() {
        let ruleset = "\
table ip firewalld {
  chain nat_POSTROUTING {
    oifname \"eth0\" masquerade
  }
}
table inet rustynet_g3 {
  chain forward {
    iifname \"rustynet0\" oifname \"eth0\" ip saddr 100.64.0.0/10 accept
  }
}";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            reasons.iter().any(|r| r.contains("must not contain NAT")),
            "a foreign masquerade must still fail blind_exit: {reasons:?}"
        );
    }

    #[test]
    fn builder_emits_mesh_scoped_forward_without_nat() {
        let cmds = build_linux_blind_exit_forward_commands(&config(), "rustynet_g3").unwrap();
        // flush, ct-accept, mesh-scoped accept — exactly three, no masquerade.
        assert_eq!(cmds.len(), 3);
        assert_eq!(
            cmds[0],
            ["flush", "chain", "inet", "rustynet_g3", "forward"]
        );
        assert_eq!(
            cmds[2],
            [
                "add",
                "rule",
                "inet",
                "rustynet_g3",
                "forward",
                "iifname",
                "rustynet0",
                "oifname",
                "eth0",
                "ip",
                "saddr",
                "100.64.0.0/10",
                "accept"
            ]
        );
        assert!(
            cmds.iter()
                .all(|argv| !argv.iter().any(|tok| tok == "masquerade"))
        );
    }

    #[test]
    fn builder_uses_ip6_family_for_ula_mesh() {
        let cfg = LinuxBlindExitConfig::new("rustynet0", "eth0", "fd7a::/48").unwrap();
        let cmds = build_linux_blind_exit_forward_commands(&cfg, "rustynet").unwrap();
        assert!(cmds[2].iter().any(|tok| tok == "ip6"));
        assert!(cmds[2].iter().all(|tok| tok != "ip"));
    }

    #[test]
    fn builder_rejects_default_route_mesh_cidr_killswitch_bypass() {
        for hostile in ["0.0.0.0/0", "::/0", "0.0.0.0/1", "8.8.8.0/24"] {
            LinuxBlindExitConfig::new("rustynet0", "eth0", hostile).expect_err(&format!(
                "{hostile} must be rejected as a mesh egress source"
            ));
        }
    }

    #[test]
    fn builder_rejects_default_route_mesh_cidr_at_render_time() {
        let mut cfg = config();
        cfg.mesh_cidr = "0.0.0.0/0".to_owned();
        build_linux_blind_exit_forward_commands(&cfg, "rustynet")
            .expect_err("render must fail closed on a default-route mesh CIDR");
    }

    #[test]
    fn builder_rejects_identical_tunnel_and_egress() {
        LinuxBlindExitConfig::new("rustynet0", "rustynet0", "100.64.0.0/10")
            .expect_err("tunnel and egress must differ");
    }

    #[test]
    fn builder_rejects_injection_in_interface_name() {
        LinuxBlindExitConfig::new("rustynet0; rm -rf /", "eth0", "100.64.0.0/10")
            .expect_err("interface name with shell metacharacters must fail");
        build_linux_blind_exit_forward_commands(&config(), "rustynet; drop")
            .expect_err("table name with metacharacters must fail");
    }

    #[test]
    fn evaluator_accepts_intact_posture() {
        // A representative `nft list ruleset` dump (interface names quoted as
        // nft renders them) carrying the hardened forward chain and no NAT.
        let ruleset = "\
table inet rustynet_g3 {
    chain killswitch {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oifname \"rustynet0\" accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname \"rustynet0\" oifname \"eth0\" ip saddr 100.64.0.0/10 accept
    }
}
";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(reasons.is_empty(), "{reasons:?}");
    }

    #[test]
    fn evaluator_rejects_masquerade_nat() {
        let ruleset = "\
table inet rustynet_g3 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname \"rustynet0\" oifname \"eth0\" ip saddr 100.64.0.0/10 accept
    }
}
table ip rustynet_nat_g3 {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"eth0\" masquerade
    }
}
";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            reasons.iter().any(|r| r.contains("must not contain NAT")),
            "{reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unrestricted_tunnel_egress_forward() {
        let ruleset = "\
table inet rustynet_g3 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname \"rustynet0\" oifname \"eth0\" accept
    }
}
";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("unrestricted") && r.contains("forward")),
            "{reasons:?}"
        );
        // ...and it is still flagged as missing the mesh-scoped allow.
        assert!(
            reasons.iter().any(|r| r.contains("mesh-scoped final-hop")),
            "{reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_own_egress_leak() {
        let ruleset = "\
table inet rustynet_g3 {
    chain killswitch {
        type filter hook output priority filter; policy drop;
        oifname \"rustynet0\" accept
        oifname \"eth0\" accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname \"rustynet0\" oifname \"eth0\" ip saddr 100.64.0.0/10 accept
    }
}
";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            reasons.iter().any(|r| r.contains("own-egress")),
            "{reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_mesh_scoped_allow() {
        let ruleset = "\
table inet rustynet_g3 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
    }
}
";
        let reasons = evaluate_linux_blind_exit_ruleset(ruleset, &config());
        assert!(
            reasons.iter().any(|r| r.contains("mesh-scoped final-hop")),
            "{reasons:?}"
        );
    }

    #[test]
    fn cleanup_policy_keeps_posture_except_factory_reset() {
        for event in [
            LinuxBlindExitCleanupEvent::DaemonShutdown,
            LinuxBlindExitCleanupEvent::KeyRotation,
            LinuxBlindExitCleanupEvent::FailClosedTransition,
            LinuxBlindExitCleanupEvent::CrashRecovery,
        ] {
            assert!(
                !should_remove_linux_blind_exit_posture(event),
                "{event:?} must leave the blind_exit posture installed"
            );
        }
        assert!(should_remove_linux_blind_exit_posture(
            LinuxBlindExitCleanupEvent::FactoryReset
        ));
    }
}
