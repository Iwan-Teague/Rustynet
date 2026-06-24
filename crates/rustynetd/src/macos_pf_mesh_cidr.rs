//! Strict validation for a mesh CIDR that is used as the **source** of a
//! macOS `pf` egress rule (`pass out quick on <egress> from <mesh_cidr> to
//! any` for `blind_exit`, and `nat on <egress> from <mesh_cidr> -> (egress)`
//! for the regular exit).
//!
//! Threat model (audit major #5 follow-up). The macOS privileged-helper
//! boundary re-renders all `pf` rule text from a structured spec, but the
//! daemon still chooses *parameters* — including the mesh CIDR. A daemon
//! compromised to the helper's uid that supplies `mesh_cidr = 0.0.0.0/0`
//! (or `::/0`, or any globally-routable supernet) renders
//! `pass out quick on en0 inet from 0.0.0.0/0 to any keep state`. Because pf
//! `quick` is first-match-wins, that rule passes **all** outbound traffic on
//! the physical egress — including local-origin egress — *before* the terminal
//! `block drop out quick all` is consulted, silently defeating the
//! `blind_exit` egress killswitch and the default-deny mandate (CLAUDE.md
//! §3/§10.4). The plain prefix-range check (`prefix <= max`) accepts prefix 0,
//! so neither it, the helper-side rule-shape assert, nor the self-referential
//! per-kind evaluator (which recomputes its expected rule *from the same*
//! daemon CIDR) catches it.
//!
//! The fix: the mesh egress source must be a **bounded private / CGNAT / ULA**
//! network — one that can never contain a globally-routable address (and so can
//! never carry the host's own public egress address). This is exactly what a
//! legitimate Rustynet mesh CIDR is (RFC 6598 `100.64.0.0/10`), so it never
//! false-rejects a real deployment while structurally foreclosing the bypass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 supernets a mesh egress source CIDR may be contained within:
/// RFC 1918 private space + RFC 6598 CGNAT (the Rustynet mesh range).
const ALLOWED_IPV4_MESH_SUPERNETS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

/// IPv6 supernets a mesh egress source CIDR may be contained within:
/// RFC 4193 ULA (`fc00::/7`, where Rustynet ULA mesh addresses live) +
/// link-local (`fe80::/10`).
const ALLOWED_IPV6_MESH_SUPERNETS: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
];

fn ipv4_contained(addr: Ipv4Addr, prefix: u8, net: Ipv4Addr, net_prefix: u8) -> bool {
    if prefix < net_prefix {
        return false;
    }
    let mask: u32 = if net_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(net_prefix))
    };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

fn ipv6_contained(addr: Ipv6Addr, prefix: u8, net: Ipv6Addr, net_prefix: u8) -> bool {
    if prefix < net_prefix {
        return false;
    }
    let mask: u128 = if net_prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(net_prefix))
    };
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}

/// Validate that `value` is a syntactically valid CIDR **and** is fully
/// contained within an allowed private/CGNAT/ULA supernet, so it can never be
/// used to author a `pass out`/`nat` rule whose source matches a globally
/// routable (or default-route) range. Fails closed on any parse error or any
/// non-contained range.
pub(crate) fn validate_mesh_egress_source_cidr(value: &str) -> Result<(), String> {
    let (addr_raw, prefix_raw) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid mesh CIDR (expected addr/prefix): {value:?}"))?;
    let ip: IpAddr = addr_raw
        .parse()
        .map_err(|_| format!("invalid mesh CIDR address: {value:?}"))?;
    let prefix: u8 = prefix_raw
        .parse()
        .map_err(|_| format!("invalid mesh CIDR prefix: {value:?}"))?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(format!("invalid mesh CIDR prefix: {value:?}"));
    }

    let contained = match ip {
        IpAddr::V4(v4) => ALLOWED_IPV4_MESH_SUPERNETS
            .iter()
            .any(|(net, net_prefix)| ipv4_contained(v4, prefix, *net, *net_prefix)),
        IpAddr::V6(v6) => ALLOWED_IPV6_MESH_SUPERNETS
            .iter()
            .any(|(net, net_prefix)| ipv6_contained(v6, prefix, *net, *net_prefix)),
    };

    if !contained {
        return Err(format!(
            "mesh egress source CIDR must be a bounded private/CGNAT/ULA range \
             (RFC1918, RFC6598 100.64.0.0/10, or RFC4193 fc00::/7); a global or \
             default-route range would carry local-origin egress past the \
             killswitch: {value:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_mesh_egress_source_cidr;

    #[test]
    fn accepts_legitimate_mesh_ranges() {
        for cidr in [
            "100.64.0.0/10", // Rustynet CGNAT mesh
            "100.64.1.0/24",
            "10.0.0.0/8",
            "10.42.0.0/16",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "fc00::/7",
            "fd7a::/48", // ULA mesh seen in the exit tests
            "fe80::/10",
        ] {
            validate_mesh_egress_source_cidr(cidr)
                .unwrap_or_else(|err| panic!("{cidr} should be accepted: {err}"));
        }
    }

    #[test]
    fn rejects_default_route_and_global_supernets() {
        for cidr in [
            "0.0.0.0/0",    // the killswitch-bypass exploit
            "::/0",         // IPv6 variant
            "0.0.0.0/1",    // half of IPv4, includes public egress addrs
            "128.0.0.0/1",  // upper half (public)
            "8.8.8.0/24",   // a public range
            "100.0.0.0/8",  // supernet of CGNAT but spills outside 100.64/10
            "172.16.0.0/8", // wider than the 172.16/12 private block
            "2001:db8::/32",
        ] {
            validate_mesh_egress_source_cidr(cidr)
                .expect_err(&format!("{cidr} must be rejected as a mesh egress source"));
        }
    }

    #[test]
    fn rejects_malformed() {
        for cidr in ["", "10.0.0.0", "not-a-cidr/8", "10.0.0.0/33", "fc00::/200"] {
            validate_mesh_egress_source_cidr(cidr)
                .expect_err(&format!("{cidr} must be rejected as malformed"));
        }
    }
}
