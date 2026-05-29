//! macOS PF policy for the `blind_exit` role.
//!
//! The reviewed posture is stricter than the generic macOS killswitch:
//! local-origin outbound traffic may leave only through the RustyNet
//! tunnel interface, while forwarded mesh-exit traffic may leave the
//! configured egress interface only when it originated from the mesh CIDR.
//! No `route-to` / `reply-to` / `dup-to` rules are allowed because they
//! would silently route around the reviewed final-hop path.

use std::net::IpAddr;

pub const DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR: &str = "com.rustynet/blind_exit";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosBlindExitManagementCidr {
    pub family: &'static str,
    pub cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosBlindExitPfConfig {
    pub tunnel_interface: String,
    pub egress_interface: String,
    pub mesh_cidr: String,
    pub anchor_name: String,
    pub ipv6_tunnel_allowed: bool,
    pub dns_protected: bool,
    pub management_ssh_allow_cidrs: Vec<MacosBlindExitManagementCidr>,
}

impl MacosBlindExitPfConfig {
    pub fn new(
        tunnel_interface: impl Into<String>,
        egress_interface: impl Into<String>,
        mesh_cidr: impl Into<String>,
    ) -> Result<Self, String> {
        let config = Self {
            tunnel_interface: tunnel_interface.into(),
            egress_interface: egress_interface.into(),
            mesh_cidr: mesh_cidr.into(),
            anchor_name: DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR.to_owned(),
            ipv6_tunnel_allowed: true,
            dns_protected: false,
            management_ssh_allow_cidrs: Vec::new(),
        };
        validate_macos_blind_exit_pf_config(&config)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosBlindExitCleanupEvent {
    DaemonShutdown,
    KeyRotation,
    FailClosedTransition,
    CrashRecovery,
    FactoryReset,
}

pub fn should_remove_macos_blind_exit_anchor(event: MacosBlindExitCleanupEvent) -> bool {
    matches!(event, MacosBlindExitCleanupEvent::FactoryReset)
}

pub fn is_macos_blind_exit_anchor(anchor: &str) -> bool {
    anchor == DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR
}

pub fn build_macos_blind_exit_pf_rules(config: &MacosBlindExitPfConfig) -> Result<String, String> {
    validate_macos_blind_exit_pf_config(config)?;
    let mesh_family = pf_family_for_cidr(config.mesh_cidr.as_str())?;
    let mut rules = String::new();
    rules.push_str("set block-policy drop\n");

    for cidr in &config.management_ssh_allow_cidrs {
        validate_pf_family(cidr.family)?;
        validate_cidr(cidr.cidr.as_str())?;
        rules.push_str(&format!(
            "pass in quick {} proto tcp from {} to any port 22 keep state\n",
            cidr.family, cidr.cidr
        ));
    }

    if config.dns_protected {
        // pf grammar: `[action] [direction] [quick] [on <iface>] [<af>] [proto <p>] ...`
        // The address family token (inet / inet6) MUST come after `on <iface>`.
        // macOS pfctl rejects `inet on <iface>` with `syntax error`
        // (verified against Phase 24 lab macOS 26.5).
        rules.push_str(&format!(
            "pass out quick on {} inet proto udp to any port 53 keep state\n",
            config.tunnel_interface
        ));
        rules.push_str(&format!(
            "pass out quick on {} inet proto tcp to any port 53 keep state\n",
            config.tunnel_interface
        ));
        rules.push_str("block drop out quick inet proto udp to any port 53\n");
        rules.push_str("block drop out quick inet proto tcp to any port 53\n");
    }

    rules.push_str(&format!(
        "pass out quick on {} inet all keep state\n",
        config.tunnel_interface
    ));
    if config.ipv6_tunnel_allowed {
        rules.push_str(&format!(
            "pass out quick on {} inet6 all keep state\n",
            config.tunnel_interface
        ));
    }
    rules.push_str(&format!(
        "pass in quick on {} {} from {} to any keep state\n",
        config.tunnel_interface, mesh_family, config.mesh_cidr
    ));
    rules.push_str(&format!(
        "pass out quick on {} {} from {} to any keep state\n",
        config.egress_interface, mesh_family, config.mesh_cidr
    ));
    if !config.ipv6_tunnel_allowed {
        rules.push_str("block drop out quick inet6 all\n");
    }
    rules.push_str("block drop out quick all\n");
    Ok(rules)
}

pub fn evaluate_macos_blind_exit_pf_rules(
    rules: &str,
    config: &MacosBlindExitPfConfig,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Err(err) = validate_macos_blind_exit_pf_config(config) {
        reasons.push(err);
        return reasons;
    }
    let mesh_family = match pf_family_for_cidr(config.mesh_cidr.as_str()) {
        Ok(value) => value,
        Err(err) => {
            reasons.push(err);
            return reasons;
        }
    };
    let normalized: Vec<String> = rules.lines().map(normalize_pf_rule).collect();

    if !normalized
        .iter()
        .any(|line| line == "block drop out quick all")
    {
        reasons.push("blind_exit PF rules missing terminal `block drop out quick all`".to_owned());
    }
    if contains_forbidden_route_primitive(&normalized) {
        reasons.push(
            "blind_exit PF rules must not contain route-to/reply-to/dup-to bypass primitives"
                .to_owned(),
        );
    }

    let tunnel_v4 = format!(
        "pass out quick on {} inet all keep state",
        config.tunnel_interface
    );
    if !normalized.iter().any(|line| line == &tunnel_v4) {
        reasons.push(format!(
            "blind_exit PF rules missing local tunnel egress allow on {}",
            config.tunnel_interface
        ));
    }
    if config.ipv6_tunnel_allowed {
        let tunnel_v6 = format!(
            "pass out quick on {} inet6 all keep state",
            config.tunnel_interface
        );
        if !normalized.iter().any(|line| line == &tunnel_v6) {
            reasons.push(format!(
                "blind_exit PF rules missing IPv6 tunnel egress allow on {}",
                config.tunnel_interface
            ));
        }
    }

    let mesh_in = format!(
        "pass in quick on {} {} from {} to any keep state",
        config.tunnel_interface, mesh_family, config.mesh_cidr
    );
    if !normalized.iter().any(|line| line == &mesh_in) {
        reasons.push(format!(
            "blind_exit PF rules missing mesh ingress allow from {} on {}",
            config.mesh_cidr, config.tunnel_interface
        ));
    }

    let mesh_out = format!(
        "pass out quick on {} {} from {} to any keep state",
        config.egress_interface, mesh_family, config.mesh_cidr
    );
    if !normalized.iter().any(|line| line == &mesh_out) {
        reasons.push(format!(
            "blind_exit PF rules missing mesh-only final-hop egress allow on {}",
            config.egress_interface
        ));
    }

    for line in normalized.iter().filter(|line| is_pass_out_rule(line)) {
        if line.contains(&format!(" on {} ", config.tunnel_interface)) {
            continue;
        }
        if line == &mesh_out {
            continue;
        }
        reasons.push(format!(
            "blind_exit PF rules contain unreviewed non-tunnel outbound pass rule: {line}"
        ));
    }

    if config.dns_protected {
        for proto in ["udp", "tcp"] {
            let pass = format!(
                "pass out quick on {} inet proto {} to any port 53 keep state",
                config.tunnel_interface, proto
            );
            let block = format!("block drop out quick inet proto {} to any port 53", proto);
            if !normalized.iter().any(|line| line == &pass) {
                reasons.push(format!(
                    "blind_exit PF rules missing tunnel DNS {proto}/53 pass"
                ));
            }
            if !normalized.iter().any(|line| line == &block) {
                reasons.push(format!(
                    "blind_exit PF rules missing non-tunnel DNS {proto}/53 block"
                ));
            }
        }
    }

    reasons
}

fn validate_macos_blind_exit_pf_config(config: &MacosBlindExitPfConfig) -> Result<(), String> {
    validate_interface_name(config.tunnel_interface.as_str())?;
    validate_interface_name(config.egress_interface.as_str())?;
    if config.tunnel_interface == config.egress_interface {
        return Err("blind_exit tunnel and egress interfaces must differ".to_owned());
    }
    validate_cidr(config.mesh_cidr.as_str())?;
    validate_anchor_name(config.anchor_name.as_str())?;
    for cidr in &config.management_ssh_allow_cidrs {
        validate_pf_family(cidr.family)?;
        validate_cidr(cidr.cidr.as_str())?;
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
        return Err(format!(
            "invalid PF interface name for blind_exit: {value:?}"
        ));
    }
    Ok(())
}

fn validate_anchor_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || value.contains("..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(format!("invalid PF anchor name for blind_exit: {value:?}"));
    }
    Ok(())
}

fn validate_pf_family(value: &str) -> Result<(), String> {
    if value == "inet" || value == "inet6" {
        Ok(())
    } else {
        Err(format!(
            "invalid PF address family for blind_exit: {value:?}"
        ))
    }
}

fn validate_cidr(value: &str) -> Result<(), String> {
    let (addr, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR for blind_exit: {value:?}"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid CIDR address for blind_exit: {value:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("invalid CIDR prefix for blind_exit: {value:?}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("invalid CIDR prefix for blind_exit: {value:?}"));
    }
    Ok(())
}

fn pf_family_for_cidr(value: &str) -> Result<&'static str, String> {
    let addr = value
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR for blind_exit: {value:?}"))?
        .0;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid CIDR address for blind_exit: {value:?}"))?;
    Ok(if ip.is_ipv4() { "inet" } else { "inet6" })
}

fn normalize_pf_rule(line: &str) -> String {
    let collapsed = line
        .split('#')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    // `pfctl -sr` echoes the default stateful flags ("flags S/SA") on every
    // keep-state rule, even when the loaded ruleset omitted them. The rule
    // strings this module generates (and the verifier's expected strings) use
    // plain "keep state", and the live verification path feeds `pfctl -sr`
    // output back in. Strip the canonical flags token so the loaded rules
    // match: without this every keep-state allow reads as "missing" and the
    // final-hop egress allow reads as an "unreviewed non-tunnel" rule.
    collapsed.replace(" flags s/sa keep state", " keep state")
}

fn contains_forbidden_route_primitive(lines: &[String]) -> bool {
    lines.iter().any(|line| {
        line.contains(" route-to ") || line.contains(" reply-to ") || line.contains(" dup-to ")
    })
}

fn is_pass_out_rule(line: &str) -> bool {
    line.starts_with("pass ") && line.contains(" out ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MacosBlindExitPfConfig {
        MacosBlindExitPfConfig::new("rustynet0", "en0", "100.64.0.0/10").unwrap()
    }

    #[test]
    fn builder_emits_reviewed_final_hop_rules() {
        let rules = build_macos_blind_exit_pf_rules(&config()).unwrap();
        assert!(rules.contains("set block-policy drop\n"));
        assert!(rules.contains("pass out quick on rustynet0 inet all keep state\n"));
        assert!(rules.contains("pass out quick on rustynet0 inet6 all keep state\n"));
        assert!(
            rules
                .contains("pass in quick on rustynet0 inet from 100.64.0.0/10 to any keep state\n")
        );
        assert!(
            rules.contains("pass out quick on en0 inet from 100.64.0.0/10 to any keep state\n")
        );
        assert!(rules.ends_with("block drop out quick all\n"));
        assert!(evaluate_macos_blind_exit_pf_rules(&rules, &config()).is_empty());
    }

    #[test]
    fn evaluator_rejects_unreviewed_cleartext_egress() {
        let mut rules = build_macos_blind_exit_pf_rules(&config()).unwrap();
        rules.push_str("pass out quick on en0 inet all keep state\n");
        let reasons = evaluate_macos_blind_exit_pf_rules(&rules, &config());
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("unreviewed non-tunnel outbound"))
        );
    }

    #[test]
    fn evaluator_accepts_pfctl_rendered_flags_s_sa() {
        // `pfctl -sr` echoes the default "flags S/SA" on every keep-state rule.
        // The live blind_exit verification feeds that output back in, so it must
        // validate identically to the generated ("keep state") form. Regression
        // for the FailClosed where every allow read as "missing" and the
        // final-hop egress as "unreviewed".
        let cfg = config();
        let rules = "\
pass out quick on rustynet0 inet all flags S/SA keep state
pass out quick on rustynet0 inet6 all flags S/SA keep state
pass in quick on rustynet0 inet from 100.64.0.0/10 to any flags S/SA keep state
pass out quick on en0 inet from 100.64.0.0/10 to any flags S/SA keep state
block drop out quick all
";
        let reasons = evaluate_macos_blind_exit_pf_rules(rules, &cfg);
        assert!(reasons.is_empty(), "{reasons:?}");
    }

    #[test]
    fn evaluator_rejects_pf_route_bypass_primitives() {
        let mut rules = build_macos_blind_exit_pf_rules(&config()).unwrap();
        rules
            .push_str("pass out quick route-to (en1 192.0.2.1) on rustynet0 inet all keep state\n");
        let reasons = evaluate_macos_blind_exit_pf_rules(&rules, &config());
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("route-to/reply-to/dup-to"))
        );
    }

    #[test]
    fn dns_protected_builder_emits_tunnel_pass_and_global_block() {
        let mut cfg = config();
        cfg.dns_protected = true;
        let rules = build_macos_blind_exit_pf_rules(&cfg).unwrap();
        let reasons = evaluate_macos_blind_exit_pf_rules(&rules, &cfg);
        assert!(reasons.is_empty(), "{reasons:?}");
        assert!(
            rules
                .contains("pass out quick on rustynet0 inet proto udp to any port 53 keep state\n")
        );
        assert!(rules.contains("block drop out quick inet proto tcp to any port 53\n"));
    }

    #[test]
    fn cleanup_policy_keeps_blind_exit_anchor_except_factory_reset() {
        for event in [
            MacosBlindExitCleanupEvent::DaemonShutdown,
            MacosBlindExitCleanupEvent::KeyRotation,
            MacosBlindExitCleanupEvent::FailClosedTransition,
            MacosBlindExitCleanupEvent::CrashRecovery,
        ] {
            assert!(
                !should_remove_macos_blind_exit_anchor(event),
                "{event:?} must leave PF anchor installed"
            );
        }
        assert!(should_remove_macos_blind_exit_anchor(
            MacosBlindExitCleanupEvent::FactoryReset
        ));
    }

    #[test]
    fn invalid_tokens_fail_closed_before_pfctl() {
        let err = MacosBlindExitPfConfig::new("rusty net0", "en0", "100.64.0.0/10")
            .expect_err("space in interface must fail");
        assert!(err.contains("interface"));
        let mut cfg = config();
        cfg.anchor_name = "com.rustynet/../escape".to_owned();
        let err = build_macos_blind_exit_pf_rules(&cfg)
            .expect_err("anchor traversal must fail before pfctl");
        assert!(err.contains("anchor"));
    }
}
