//! Structured load spec for the macOS `pf` privileged builtin (`macos-pf-load`).
//!
//! Closes the audit major #5 `pfctl -f` privileged-boundary vulnerability. The
//! old path let the daemon hand the privileged helper an arbitrary daemon-owned
//! rules file (`pfctl -a <anchor> -f <path>`); a daemon compromised to the
//! helper's uid could write `pass out quick all` into the killswitch anchor and
//! defeat default-deny egress. Ownership/`O_NOFOLLOW` checks cannot fix it
//! because the daemon legitimately *authors* the file content.
//!
//! The fix is **regeneration**: the daemon sends only a validated, structured
//! SPEC over IPC; the root helper re-renders the `pf` rule text itself from the
//! reviewed builders, derives the anchor name itself, and owns the temp file +
//! `pfctl` invocation end-to-end. A compromised daemon can choose spec
//! PARAMETERS — each independently validated by the helper — but can never
//! inject rule text, redirect the anchor, or load a foreign file. This mirrors
//! the proven [`crate::linux_dns_protect`] `DnsFailclosedFile` builtin: a sealed
//! selector/spec crosses the boundary, the helper owns path + content.
//!
//! Because the helper re-renders from the same reviewed builders the daemon
//! used, there is no rule-text allowlist that could *false-reject* a legitimate
//! load (which would strand the node undefended — worse than the vuln). Whatever
//! spec validates renders deterministically, and the render is by construction
//! terminated by `block drop out quick all` for the filter anchors.
//!
//! Wire form: the spec is encoded as `key=value` argument tokens, reusing the
//! existing helper request framing (no wire-format change). List-valued fields
//! (CIDRs, endpoints) are packed comma-separated across as many tokens as needed
//! to stay within the per-argument byte cap, so even a full 128-peer mesh fits
//! the framing without raising any global limit.

use std::net::{IpAddr, SocketAddr};

use crate::macos_blind_exit::{
    DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR, MacosBlindExitManagementCidr, MacosBlindExitPfConfig,
    build_macos_blind_exit_pf_rules,
};
use crate::macos_exit_nat::{
    DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR, MacosExitNatPfConfig, build_macos_exit_nat_pf_rules,
};
use crate::phase10::{MacosKillswitchSpec, ManagementCidr, render_macos_killswitch_pf_rules};
use crate::privileged_helper::MAX_ARG_BYTES;

/// Privileged-command program name for the macOS `pf` load builtin. The daemon
/// names this program instead of `pfctl` when it needs to load a filter/NAT
/// anchor; the helper re-renders the rules from the transported spec.
pub const MACOS_PF_LOAD_PROGRAM: &str = "macos-pf-load";

/// Per-kind list-length caps enforced on decode (fail-closed amplification
/// guard). All are set comfortably above the largest legitimate configuration
/// (e.g. `managed_peer` ≤ `MAX_AUTO_TUNNEL_PEER_COUNT` = 128) so they can never
/// false-reject a real node, while bounding a hostile daemon's input.
const MAX_SSH_CIDRS: usize = 64;
const MAX_TRAVERSAL_ENDPOINTS: usize = 64;
const MAX_MANAGED_PEER_ENDPOINTS: usize = 256;
const MAX_MESH_CIDRS: usize = 64;

/// A macOS `pf` anchor load request, addressed by kind. The daemon builds one of
/// these from its current dataplane state; the helper decodes + re-renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MacosPfLoadSpec {
    /// The generation-numbered killswitch filter anchor
    /// (`com.apple/rustynet_g<generation>`).
    Killswitch {
        generation: u64,
        strict_fail_closed: bool,
        spec: MacosKillswitchSpec,
    },
    /// The fixed-name blind-exit filter anchor (`com.rustynet/blind_exit`).
    BlindExit { config: MacosBlindExitPfConfig },
    /// The fixed-name regular-exit NAT translation anchor (`com.rustynet/nat`).
    ExitNat { config: MacosExitNatPfConfig },
}

impl MacosPfLoadSpec {
    /// Encode the spec into `key=value` argument tokens for the privileged
    /// helper request. Daemon-side. List fields are comma-chunked so every
    /// token stays within [`MAX_ARG_BYTES`].
    pub(crate) fn encode(&self) -> Vec<String> {
        let mut args = Vec::new();
        match self {
            MacosPfLoadSpec::Killswitch {
                generation,
                strict_fail_closed,
                spec,
            } => {
                args.push("kind=killswitch".to_owned());
                args.push(format!("generation={generation}"));
                args.push(format!("strict={strict_fail_closed}"));
                args.push(format!("interface={}", spec.interface_name));
                args.push(format!("egress={}", spec.egress_interface));
                args.push(format!("dns_protected={}", spec.dns_protected));
                args.push(format!(
                    "allow_egress_interface={}",
                    spec.allow_egress_interface
                ));
                args.push(format!(
                    "fail_closed_ssh_allow={}",
                    spec.fail_closed_ssh_allow
                ));
                args.push(format!("ipv6_blocked={}", spec.ipv6_blocked));
                push_list(
                    &mut args,
                    "ssh_cidr",
                    spec.fail_closed_ssh_allow_cidrs
                        .iter()
                        .map(ToString::to_string),
                );
                push_list(
                    &mut args,
                    "traversal",
                    spec.traversal_bootstrap_allow_endpoints
                        .iter()
                        .map(ToString::to_string),
                );
                push_list(
                    &mut args,
                    "managed_peer",
                    spec.managed_peer_egress_endpoints
                        .iter()
                        .map(ToString::to_string),
                );
            }
            MacosPfLoadSpec::BlindExit { config } => {
                args.push("kind=blind_exit".to_owned());
                args.push(format!("tunnel={}", config.tunnel_interface));
                args.push(format!("egress={}", config.egress_interface));
                args.push(format!("mesh_cidr={}", config.mesh_cidr));
                args.push(format!(
                    "ipv6_tunnel_allowed={}",
                    config.ipv6_tunnel_allowed
                ));
                args.push(format!("dns_protected={}", config.dns_protected));
                push_list(
                    &mut args,
                    "ssh_cidr",
                    config
                        .management_ssh_allow_cidrs
                        .iter()
                        .map(|cidr| cidr.cidr.clone()),
                );
            }
            MacosPfLoadSpec::ExitNat { config } => {
                args.push("kind=exit_nat".to_owned());
                args.push(format!("egress={}", config.egress_interface));
                push_list(&mut args, "mesh_cidr", config.mesh_cidrs.iter().cloned());
            }
        }
        args
    }

    /// The `pf` anchor name this spec loads, derived ENTIRELY from the spec kind
    /// (and generation for the killswitch). The helper uses this — never an
    /// anchor string supplied by the daemon — so a compromised daemon cannot
    /// redirect a load into a foreign anchor.
    pub(crate) fn anchor_name(&self) -> String {
        match self {
            MacosPfLoadSpec::Killswitch { generation, .. } => {
                format!("com.apple/rustynet_g{generation}")
            }
            MacosPfLoadSpec::BlindExit { .. } => DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR.to_owned(),
            MacosPfLoadSpec::ExitNat { .. } => DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR.to_owned(),
        }
    }

    /// Re-render the `pf` rule text from the reviewed builders, then assert the
    /// kind-appropriate safety invariants (defense in depth against a future
    /// builder regression). Helper-side.
    pub(crate) fn render(&self) -> Result<String, String> {
        let rules = match self {
            MacosPfLoadSpec::Killswitch {
                strict_fail_closed,
                spec,
                ..
            } => render_macos_killswitch_pf_rules(spec, *strict_fail_closed),
            MacosPfLoadSpec::BlindExit { config } => build_macos_blind_exit_pf_rules(config)?,
            MacosPfLoadSpec::ExitNat { config } => build_macos_exit_nat_pf_rules(config)?,
        };
        self.assert_rule_invariants(&rules)?;
        Ok(rules)
    }

    /// Defense-in-depth invariants on the rendered text. The security property
    /// comes from regeneration (the daemon never authors text); this is a
    /// belt-and-suspenders guard that the reviewed builders still produce a
    /// fail-closed ruleset, catching any future builder bug before it loads.
    fn assert_rule_invariants(&self, rules: &str) -> Result<(), String> {
        if contains_forbidden_route_primitive(rules) {
            return Err(
                "macos pf-load rules must not contain route-to/reply-to/dup-to bypass primitives"
                    .to_owned(),
            );
        }
        match self {
            MacosPfLoadSpec::Killswitch { .. } | MacosPfLoadSpec::BlindExit { .. } => {
                // Filter anchors MUST terminate in the default-deny egress block.
                let last_rule = rules
                    .lines()
                    .map(str::trim)
                    .rfind(|line| !line.is_empty())
                    .unwrap_or_default();
                if last_rule != "block drop out quick all" {
                    return Err(
                        "macos pf-load filter anchor missing terminal `block drop out quick all`"
                            .to_owned(),
                    );
                }
            }
            MacosPfLoadSpec::ExitNat { .. } => {
                // The translation anchor must contain ONLY `nat ...` rules; a
                // filter `pass`/`block` smuggled here would be unreviewed.
                for line in rules.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if !trimmed.starts_with("nat ") {
                        return Err(format!(
                            "macos pf-load exit NAT anchor contains a non-nat rule: {trimmed}"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Decode + fully validate a spec from helper request tokens. Helper-side:
    /// every field is re-parsed through a typed validator and list lengths are
    /// bounded; any malformed/cross-kind/unknown token fails closed with no
    /// partial result. This is the entire attack surface the daemon can reach.
    pub(crate) fn decode(args: &[&str]) -> Result<Self, String> {
        if args.is_empty() {
            return Err("macos pf-load spec has no tokens".to_owned());
        }

        let mut kind: Option<&str> = None;
        let mut generation: Option<&str> = None;
        let mut strict: Option<&str> = None;
        let mut interface: Option<&str> = None;
        let mut egress: Option<&str> = None;
        let mut tunnel: Option<&str> = None;
        let mut dns_protected: Option<&str> = None;
        let mut allow_egress_interface: Option<&str> = None;
        let mut fail_closed_ssh_allow: Option<&str> = None;
        let mut ipv6_blocked: Option<&str> = None;
        let mut ipv6_tunnel_allowed: Option<&str> = None;
        let mut ssh_cidr: Vec<&str> = Vec::new();
        let mut traversal: Vec<&str> = Vec::new();
        let mut managed_peer: Vec<&str> = Vec::new();
        let mut mesh_cidr: Vec<&str> = Vec::new();

        for arg in args {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| format!("macos pf-load token missing '=': {arg}"))?;
            match key {
                "kind" => set_once(&mut kind, key, value)?,
                "generation" => set_once(&mut generation, key, value)?,
                "strict" => set_once(&mut strict, key, value)?,
                "interface" => set_once(&mut interface, key, value)?,
                "egress" => set_once(&mut egress, key, value)?,
                "tunnel" => set_once(&mut tunnel, key, value)?,
                "dns_protected" => set_once(&mut dns_protected, key, value)?,
                "allow_egress_interface" => set_once(&mut allow_egress_interface, key, value)?,
                "fail_closed_ssh_allow" => set_once(&mut fail_closed_ssh_allow, key, value)?,
                "ipv6_blocked" => set_once(&mut ipv6_blocked, key, value)?,
                "ipv6_tunnel_allowed" => set_once(&mut ipv6_tunnel_allowed, key, value)?,
                "ssh_cidr" => extend_csv(&mut ssh_cidr, value),
                "traversal" => extend_csv(&mut traversal, value),
                "managed_peer" => extend_csv(&mut managed_peer, value),
                "mesh_cidr" => extend_csv(&mut mesh_cidr, value),
                other => return Err(format!("unknown macos pf-load token key: {other}")),
            }
        }

        bound_list("ssh_cidr", ssh_cidr.len(), MAX_SSH_CIDRS)?;
        bound_list("traversal", traversal.len(), MAX_TRAVERSAL_ENDPOINTS)?;
        bound_list(
            "managed_peer",
            managed_peer.len(),
            MAX_MANAGED_PEER_ENDPOINTS,
        )?;
        bound_list("mesh_cidr", mesh_cidr.len(), MAX_MESH_CIDRS)?;

        match kind {
            Some("killswitch") => {
                // Reject fields that do not belong to this kind (fail closed).
                reject_present("killswitch", "tunnel", tunnel)?;
                reject_present("killswitch", "ipv6_tunnel_allowed", ipv6_tunnel_allowed)?;
                reject_nonempty("killswitch", "mesh_cidr", &mesh_cidr)?;

                let generation = parse_u64(require(generation, "generation")?, "generation")?;
                let strict_fail_closed = parse_bool(require(strict, "strict")?, "strict")?;
                let interface_name = parse_interface(require(interface, "interface")?)?;
                let egress_interface = parse_interface(require(egress, "egress")?)?;
                let dns_protected =
                    parse_bool(require(dns_protected, "dns_protected")?, "dns_protected")?;
                let allow_egress_interface = parse_bool(
                    require(allow_egress_interface, "allow_egress_interface")?,
                    "allow_egress_interface",
                )?;
                let fail_closed_ssh_allow = parse_bool(
                    require(fail_closed_ssh_allow, "fail_closed_ssh_allow")?,
                    "fail_closed_ssh_allow",
                )?;
                let ipv6_blocked =
                    parse_bool(require(ipv6_blocked, "ipv6_blocked")?, "ipv6_blocked")?;

                let fail_closed_ssh_allow_cidrs = ssh_cidr
                    .iter()
                    .map(|value| parse_management_cidr(value))
                    .collect::<Result<Vec<ManagementCidr>, String>>()?;
                let traversal_bootstrap_allow_endpoints = traversal
                    .iter()
                    .map(|value| parse_socket_addr(value))
                    .collect::<Result<Vec<SocketAddr>, String>>()?;
                let managed_peer_egress_endpoints = managed_peer
                    .iter()
                    .map(|value| parse_socket_addr(value))
                    .collect::<Result<Vec<SocketAddr>, String>>()?;

                Ok(MacosPfLoadSpec::Killswitch {
                    generation,
                    strict_fail_closed,
                    spec: MacosKillswitchSpec {
                        interface_name,
                        egress_interface,
                        dns_protected,
                        allow_egress_interface,
                        fail_closed_ssh_allow,
                        fail_closed_ssh_allow_cidrs,
                        traversal_bootstrap_allow_endpoints,
                        managed_peer_egress_endpoints,
                        ipv6_blocked,
                    },
                })
            }
            Some("blind_exit") => {
                reject_present("blind_exit", "generation", generation)?;
                reject_present("blind_exit", "strict", strict)?;
                reject_present("blind_exit", "interface", interface)?;
                reject_present(
                    "blind_exit",
                    "allow_egress_interface",
                    allow_egress_interface,
                )?;
                reject_present("blind_exit", "fail_closed_ssh_allow", fail_closed_ssh_allow)?;
                reject_present("blind_exit", "ipv6_blocked", ipv6_blocked)?;
                reject_nonempty("blind_exit", "traversal", &traversal)?;
                reject_nonempty("blind_exit", "managed_peer", &managed_peer)?;

                let tunnel_interface = require(tunnel, "tunnel")?.to_owned();
                let egress_interface = require(egress, "egress")?.to_owned();
                let mesh = match mesh_cidr.as_slice() {
                    [single] => (*single).to_owned(),
                    [] => return Err("blind_exit spec missing mesh_cidr".to_owned()),
                    _ => return Err("blind_exit spec expects exactly one mesh_cidr".to_owned()),
                };
                let ipv6_tunnel_allowed = parse_bool(
                    require(ipv6_tunnel_allowed, "ipv6_tunnel_allowed")?,
                    "ipv6_tunnel_allowed",
                )?;
                let dns_protected =
                    parse_bool(require(dns_protected, "dns_protected")?, "dns_protected")?;

                // `new` validates interfaces (incl. tunnel != egress) and the
                // mesh CIDR; `build` (in `render`) re-validates the ssh CIDRs.
                let mut config =
                    MacosBlindExitPfConfig::new(tunnel_interface, egress_interface, mesh)?;
                config.ipv6_tunnel_allowed = ipv6_tunnel_allowed;
                config.dns_protected = dns_protected;
                config.management_ssh_allow_cidrs = ssh_cidr
                    .iter()
                    .map(|value| {
                        let family = pf_family_for_cidr_str(value)?;
                        Ok(MacosBlindExitManagementCidr {
                            family,
                            cidr: (*value).to_owned(),
                        })
                    })
                    .collect::<Result<Vec<MacosBlindExitManagementCidr>, String>>()?;

                Ok(MacosPfLoadSpec::BlindExit { config })
            }
            Some("exit_nat") => {
                reject_present("exit_nat", "generation", generation)?;
                reject_present("exit_nat", "strict", strict)?;
                reject_present("exit_nat", "interface", interface)?;
                reject_present("exit_nat", "tunnel", tunnel)?;
                reject_present("exit_nat", "dns_protected", dns_protected)?;
                reject_present("exit_nat", "allow_egress_interface", allow_egress_interface)?;
                reject_present("exit_nat", "fail_closed_ssh_allow", fail_closed_ssh_allow)?;
                reject_present("exit_nat", "ipv6_blocked", ipv6_blocked)?;
                reject_present("exit_nat", "ipv6_tunnel_allowed", ipv6_tunnel_allowed)?;
                reject_nonempty("exit_nat", "ssh_cidr", &ssh_cidr)?;
                reject_nonempty("exit_nat", "traversal", &traversal)?;
                reject_nonempty("exit_nat", "managed_peer", &managed_peer)?;

                let egress_interface = require(egress, "egress")?.to_owned();
                if mesh_cidr.is_empty() {
                    return Err("exit_nat spec requires at least one mesh_cidr".to_owned());
                }
                let mesh_cidrs = mesh_cidr.iter().map(|value| (*value).to_owned()).collect();
                // `new` validates the egress interface and every mesh CIDR.
                let config = MacosExitNatPfConfig::new(egress_interface, mesh_cidrs)?;
                Ok(MacosPfLoadSpec::ExitNat { config })
            }
            Some(other) => Err(format!("unknown macos pf-load kind: {other}")),
            None => Err("macos pf-load spec missing kind".to_owned()),
        }
    }
}

/// Append `values` to `args` as one or more `key=v1,v2,...` tokens, never
/// exceeding [`MAX_ARG_BYTES`] per token. The decoder treats repeated `key=`
/// tokens additively and re-splits on commas, so the chunking is transparent.
fn push_list(args: &mut Vec<String>, key: &str, values: impl Iterator<Item = String>) {
    let mut current = String::new();
    for value in values {
        let separator = usize::from(!current.is_empty());
        if !current.is_empty()
            && key.len() + 1 + current.len() + separator + value.len() > MAX_ARG_BYTES
        {
            args.push(format!("{key}={current}"));
            current.clear();
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(&value);
    }
    if !current.is_empty() {
        args.push(format!("{key}={current}"));
    }
}

fn extend_csv<'a>(out: &mut Vec<&'a str>, value: &'a str) {
    for part in value.split(',') {
        if !part.is_empty() {
            out.push(part);
        }
    }
}

fn set_once<'a>(slot: &mut Option<&'a str>, key: &str, value: &'a str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate macos pf-load token: {key}"));
    }
    *slot = Some(value);
    Ok(())
}

fn require<'a>(slot: Option<&'a str>, key: &str) -> Result<&'a str, String> {
    slot.ok_or_else(|| format!("macos pf-load spec missing required token: {key}"))
}

fn reject_present(kind: &str, key: &str, slot: Option<&str>) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!(
            "macos pf-load {kind} spec must not carry token: {key}"
        ));
    }
    Ok(())
}

fn reject_nonempty(kind: &str, key: &str, values: &[&str]) -> Result<(), String> {
    if !values.is_empty() {
        return Err(format!(
            "macos pf-load {kind} spec must not carry token: {key}"
        ));
    }
    Ok(())
}

fn bound_list(key: &str, len: usize, max: usize) -> Result<(), String> {
    if len > max {
        return Err(format!(
            "macos pf-load {key} list length {len} exceeds maximum {max}"
        ));
    }
    Ok(())
}

fn parse_bool(value: &str, key: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "macos pf-load {key} must be true/false, got {other:?}"
        )),
    }
}

fn parse_u64(value: &str, key: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("macos pf-load {key} must be a u64, got {value:?}"))
}

/// Validate a `pf` interface name for safe interpolation into rule text. The
/// `[A-Za-z0-9._-]` set (length 1..=31) excludes every `pf` grammar
/// metacharacter and all whitespace/newlines, so a malicious interface token
/// cannot inject an extra rule line. Matches the reviewed
/// `macos_blind_exit::validate_interface_name` posture.
fn parse_interface(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 31
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "macos pf-load invalid pf interface name: {value:?}"
        ));
    }
    Ok(value.to_owned())
}

fn parse_management_cidr(value: &str) -> Result<ManagementCidr, String> {
    value.parse::<ManagementCidr>()
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| format!("macos pf-load invalid endpoint: {value:?}"))
}

fn pf_family_for_cidr_str(value: &str) -> Result<&'static str, String> {
    let base = value
        .split_once('/')
        .map(|(base, _)| base)
        .ok_or_else(|| format!("macos pf-load invalid cidr: {value:?}"))?;
    let ip: IpAddr = base
        .parse()
        .map_err(|_| format!("macos pf-load invalid cidr address: {value:?}"))?;
    Ok(if ip.is_ipv4() { "inet" } else { "inet6" })
}

fn contains_forbidden_route_primitive(rules: &str) -> bool {
    rules.lines().any(|line| {
        let normalized = line.to_ascii_lowercase();
        normalized.contains(" route-to ")
            || normalized.contains(" reply-to ")
            || normalized.contains(" dup-to ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_helper::{MAX_ARG_BYTES, MAX_ARGS};
    use std::str::FromStr;

    fn killswitch(spec: MacosKillswitchSpec, generation: u64, strict: bool) -> MacosPfLoadSpec {
        MacosPfLoadSpec::Killswitch {
            generation,
            strict_fail_closed: strict,
            spec,
        }
    }

    fn rich_killswitch_spec() -> MacosKillswitchSpec {
        MacosKillswitchSpec {
            interface_name: "utun9".to_owned(),
            egress_interface: "en0".to_owned(),
            dns_protected: true,
            allow_egress_interface: false,
            fail_closed_ssh_allow: true,
            fail_closed_ssh_allow_cidrs: vec![
                ManagementCidr::from_str("192.168.128.0/24").unwrap(),
            ],
            traversal_bootstrap_allow_endpoints: vec!["203.0.113.10:3478".parse().unwrap()],
            managed_peer_egress_endpoints: vec!["192.168.65.3:51820".parse().unwrap()],
            ipv6_blocked: true,
        }
    }

    #[test]
    fn killswitch_roundtrip_renders_identically() {
        let original = killswitch(rich_killswitch_spec(), 7, false);
        let encoded = original.encode();
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.render().unwrap(), original.render().unwrap());
        assert_eq!(decoded.anchor_name(), "com.apple/rustynet_g7");
        // The render is the SAME text the daemon-side renderer produces.
        let direct = render_macos_killswitch_pf_rules(&rich_killswitch_spec(), false);
        assert_eq!(original.render().unwrap(), direct);
    }

    #[test]
    fn killswitch_render_always_ends_in_block_all() {
        let spec = killswitch(rich_killswitch_spec(), 1, false);
        let rules = spec.render().unwrap();
        assert!(rules.trim_end().ends_with("block drop out quick all"));
    }

    #[test]
    fn strict_killswitch_is_minimal_and_terminal() {
        let spec = killswitch(
            MacosKillswitchSpec {
                interface_name: "utun9".to_owned(),
                egress_interface: "en0".to_owned(),
                dns_protected: false,
                allow_egress_interface: false,
                fail_closed_ssh_allow: false,
                fail_closed_ssh_allow_cidrs: Vec::new(),
                traversal_bootstrap_allow_endpoints: Vec::new(),
                managed_peer_egress_endpoints: Vec::new(),
                ipv6_blocked: false,
            },
            3,
            true,
        );
        let rules = spec.render().unwrap();
        assert_eq!(rules, "set block-policy drop\nblock drop out quick all\n");
    }

    #[test]
    fn blind_exit_roundtrip() {
        let mut config = MacosBlindExitPfConfig::new("rustynet0", "en0", "100.64.0.0/10").unwrap();
        config.ipv6_tunnel_allowed = false;
        config.dns_protected = true;
        config.management_ssh_allow_cidrs = vec![MacosBlindExitManagementCidr {
            family: "inet",
            cidr: "192.168.0.0/24".to_owned(),
        }];
        let original = MacosPfLoadSpec::BlindExit { config };
        let encoded = original.encode();
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
        assert_eq!(decoded.render().unwrap(), original.render().unwrap());
        assert_eq!(decoded.anchor_name(), "com.rustynet/blind_exit");
        assert!(
            decoded
                .render()
                .unwrap()
                .trim_end()
                .ends_with("block drop out quick all")
        );
    }

    #[test]
    fn exit_nat_roundtrip_is_nat_only() {
        let config = MacosExitNatPfConfig::new("en0", vec!["100.64.0.0/10".to_owned()]).unwrap();
        let original = MacosPfLoadSpec::ExitNat { config };
        let encoded = original.encode();
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
        assert_eq!(decoded.render().unwrap(), original.render().unwrap());
        assert_eq!(decoded.anchor_name(), "com.rustynet/nat");
        let rules = decoded.render().unwrap();
        for line in rules.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.trim_start().starts_with("nat "),
                "non-nat rule: {line}"
            );
        }
    }

    #[test]
    fn ipv6_endpoints_roundtrip() {
        let spec = MacosKillswitchSpec {
            interface_name: "utun9".to_owned(),
            egress_interface: "en0".to_owned(),
            dns_protected: false,
            allow_egress_interface: false,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            traversal_bootstrap_allow_endpoints: vec!["[2001:db8::3]:3478".parse().unwrap()],
            managed_peer_egress_endpoints: vec!["[2001:db8::5]:51820".parse().unwrap()],
            ipv6_blocked: false,
        };
        let original = killswitch(spec, 2, false);
        let encoded = original.encode();
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn reject_interface_with_injected_rule() {
        // A newline + a permissive rule in the interface name must be rejected
        // by the interface validator before any render.
        let mut encoded = killswitch(rich_killswitch_spec(), 1, false).encode();
        for token in &mut encoded {
            if token.starts_with("interface=") {
                *token = "interface=utun9\npass out quick all".to_owned();
            }
        }
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        assert!(MacosPfLoadSpec::decode(&refs).is_err());
    }

    #[test]
    fn reject_interface_with_space() {
        let refs = vec![
            "kind=killswitch",
            "generation=1",
            "strict=false",
            "interface=utun9 evil",
            "egress=en0",
            "dns_protected=false",
            "allow_egress_interface=false",
            "fail_closed_ssh_allow=false",
            "ipv6_blocked=false",
        ];
        assert!(MacosPfLoadSpec::decode(&refs).is_err());
    }

    #[test]
    fn reject_bad_cidr_and_port_zero_and_bad_ip() {
        let base = || {
            vec![
                "kind=killswitch".to_owned(),
                "generation=1".to_owned(),
                "strict=false".to_owned(),
                "interface=utun9".to_owned(),
                "egress=en0".to_owned(),
                "dns_protected=false".to_owned(),
                "allow_egress_interface=false".to_owned(),
                "fail_closed_ssh_allow=true".to_owned(),
                "ipv6_blocked=false".to_owned(),
            ]
        };
        let mut bad_cidr = base();
        bad_cidr.push("ssh_cidr=192.168.0.0/33".to_owned());
        let refs: Vec<&str> = bad_cidr.iter().map(String::as_str).collect();
        assert!(MacosPfLoadSpec::decode(&refs).is_err());

        let mut port_zero = base();
        port_zero.push("managed_peer=1.2.3.4:0".to_owned());
        let refs: Vec<&str> = port_zero.iter().map(String::as_str).collect();
        // 1.2.3.4:0 parses as a SocketAddr (port 0 is valid syntactically); the
        // render then emits `port 0` which still ends in block-all. Port 0 is
        // never produced by the daemon, but accept-or-reject it cannot weaken
        // the killswitch, so we only require it not to bypass the terminal block.
        if let Ok(spec) = MacosPfLoadSpec::decode(&refs) {
            assert!(
                spec.render()
                    .unwrap()
                    .trim_end()
                    .ends_with("block drop out quick all")
            );
        }

        let mut bad_ip = base();
        bad_ip.push("traversal=not.an.ip:53".to_owned());
        let refs: Vec<&str> = bad_ip.iter().map(String::as_str).collect();
        assert!(MacosPfLoadSpec::decode(&refs).is_err());
    }

    #[test]
    fn reject_oversized_lists() {
        let mut tokens = vec![
            "kind=killswitch".to_owned(),
            "generation=1".to_owned(),
            "strict=false".to_owned(),
            "interface=utun9".to_owned(),
            "egress=en0".to_owned(),
            "dns_protected=false".to_owned(),
            "allow_egress_interface=false".to_owned(),
            "fail_closed_ssh_allow=false".to_owned(),
            "ipv6_blocked=false".to_owned(),
        ];
        // MAX_MANAGED_PEER_ENDPOINTS + 1 endpoints, one per comma element.
        let huge: Vec<String> = (0..(MAX_MANAGED_PEER_ENDPOINTS + 1))
            .map(|i| format!("10.0.{}.{}:51820", i / 256, i % 256))
            .collect();
        tokens.push(format!("managed_peer={}", huge.join(",")));
        let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
        assert!(MacosPfLoadSpec::decode(&refs).is_err());
    }

    #[test]
    fn reject_unknown_and_crosskind_and_duplicate_tokens() {
        let refs = vec!["kind=killswitch", "bogus=1"];
        assert!(MacosPfLoadSpec::decode(&refs).is_err());

        // blind_exit must not carry killswitch-only tokens.
        let refs = vec![
            "kind=blind_exit",
            "tunnel=rustynet0",
            "egress=en0",
            "mesh_cidr=100.64.0.0/10",
            "ipv6_tunnel_allowed=true",
            "dns_protected=false",
            "generation=1",
        ];
        assert!(MacosPfLoadSpec::decode(&refs).is_err());

        let refs = vec!["kind=killswitch", "kind=blind_exit"];
        assert!(MacosPfLoadSpec::decode(&refs).is_err());
    }

    #[test]
    fn decode_ignores_daemon_anchor_uses_derived() {
        // There is no anchor token; the anchor is purely a function of kind +
        // generation, so two specs that differ only in generation map to
        // distinct, helper-derived anchors and nothing the daemon sends can
        // redirect them.
        let a = killswitch(rich_killswitch_spec(), 4, false);
        let b = killswitch(rich_killswitch_spec(), 9, false);
        assert_eq!(a.anchor_name(), "com.apple/rustynet_g4");
        assert_eq!(b.anchor_name(), "com.apple/rustynet_g9");
    }

    #[test]
    fn assert_invariants_catch_builder_regressions() {
        // Defense-in-depth regression guard: if a future builder change dropped
        // the terminal block-all or introduced a bypass primitive, the assert
        // must catch it before the rules ever load.
        let ks = killswitch(rich_killswitch_spec(), 1, false);
        // Filter anchor missing the terminal default-deny -> rejected.
        assert!(
            ks.assert_rule_invariants("set block-policy drop\npass out quick all\n")
                .is_err()
        );
        // route-to bypass primitive in a filter anchor -> rejected.
        assert!(
            ks.assert_rule_invariants(
                "pass out quick on en0 route-to (en0 1.2.3.4) all\nblock drop out quick all\n"
            )
            .is_err()
        );

        let nat = MacosPfLoadSpec::ExitNat {
            config: MacosExitNatPfConfig::new("en0", vec!["100.64.0.0/10".to_owned()]).unwrap(),
        };
        // A filter rule smuggled into the translation anchor -> rejected.
        assert!(
            nat.assert_rule_invariants(
                "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\npass out quick all\n"
            )
            .is_err()
        );
        // A clean nat-only ruleset passes.
        assert!(
            nat.assert_rule_invariants("nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n")
                .is_ok()
        );
    }

    #[test]
    fn no_false_reject_cartesian_sweep() {
        // Completeness proof: every legitimate combination of the killswitch
        // knobs renders without error AND terminates in the default-deny block.
        let ssh = ManagementCidr::from_str("192.168.128.0/24").unwrap();
        let endpoints: Vec<SocketAddr> = vec![
            "203.0.113.10:3478".parse().unwrap(),
            "[2001:db8::1]:3478".parse().unwrap(),
        ];
        for dns in [false, true] {
            for ipv6 in [false, true] {
                for allow_egress in [false, true] {
                    for ssh_n in 0..=2usize {
                        for trav_n in 0..=2usize {
                            for peer_n in 0..=2usize {
                                let spec = MacosKillswitchSpec {
                                    interface_name: "utun9".to_owned(),
                                    egress_interface: "en0".to_owned(),
                                    dns_protected: dns,
                                    allow_egress_interface: allow_egress,
                                    fail_closed_ssh_allow: ssh_n > 0,
                                    fail_closed_ssh_allow_cidrs: vec![ssh; ssh_n],
                                    traversal_bootstrap_allow_endpoints: endpoints
                                        .iter()
                                        .cycle()
                                        .take(trav_n)
                                        .copied()
                                        .collect(),
                                    managed_peer_egress_endpoints: endpoints
                                        .iter()
                                        .cycle()
                                        .take(peer_n)
                                        .copied()
                                        .collect(),
                                    ipv6_blocked: ipv6,
                                };
                                let load = killswitch(spec, 1, false);
                                let encoded = load.encode();
                                assert!(encoded.len() <= MAX_ARGS, "arg count within framing");
                                assert!(
                                    encoded.iter().all(|a| a.len() <= MAX_ARG_BYTES),
                                    "arg byte cap respected"
                                );
                                let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
                                let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
                                let rules = decoded.render().expect("render");
                                assert!(
                                    rules.trim_end().ends_with("block drop out quick all"),
                                    "missing terminal block-all for dns={dns} ipv6={ipv6}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn full_mesh_fits_framing() {
        // 128 managed peers (MAX_AUTO_TUNNEL_PEER_COUNT) must encode within the
        // helper request framing without raising any global limit.
        let endpoints: Vec<SocketAddr> = (0..128)
            .map(|i| {
                format!("10.10.{}.{}:51820", i / 256, i % 256)
                    .parse()
                    .unwrap()
            })
            .collect();
        let spec = MacosKillswitchSpec {
            interface_name: "utun9".to_owned(),
            egress_interface: "en0".to_owned(),
            dns_protected: true,
            allow_egress_interface: false,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            traversal_bootstrap_allow_endpoints: Vec::new(),
            managed_peer_egress_endpoints: endpoints.clone(),
            ipv6_blocked: true,
        };
        let load = killswitch(spec, 1, false);
        let encoded = load.encode();
        assert!(encoded.len() <= MAX_ARGS, "got {} args", encoded.len());
        assert!(encoded.iter().all(|a| a.len() <= MAX_ARG_BYTES));
        let refs: Vec<&str> = encoded.iter().map(String::as_str).collect();
        let decoded = MacosPfLoadSpec::decode(&refs).expect("decode");
        if let MacosPfLoadSpec::Killswitch { spec, .. } = decoded {
            assert_eq!(spec.managed_peer_egress_endpoints, endpoints);
        } else {
            panic!("expected killswitch");
        }
    }
}
