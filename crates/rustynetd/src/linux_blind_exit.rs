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
    if normalized.iter().any(|line| line.contains("masquerade"))
        || normalized.iter().any(|line| line.contains(" snat "))
        || normalized.iter().any(|line| line.contains(" dnat "))
    {
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
