//! Linux DNS fail-closed enforcement for protected mode — Option 2: the
//! rustynet resolver owns loopback DNS.
//!
//! # Why this exists
//! In protected mode the node must not resolve via off-host DNS
//! (`SecurityMinimumBar`: preserve DNS fail-closed in protected modes). The
//! `dns-failclosed` verifier ([`crate::linux_dns_failclosed`]) requires every
//! `/etc/resolv.conf` nameserver to be loopback, rejects pointing at the
//! systemd-resolved stub `127.0.0.53` while systemd-resolved holds it, and
//! flags NetworkManager `dns=default` (NM can rewrite resolv.conf off-loopback
//! on any link change). The reviewed posture is therefore: resolv.conf points
//! only at the rustynet resolver's loopback address; the resolver serves
//! mesh-zone names and refuses everything else; the nft killswitch blocks
//! off-host egress as defense-in-depth.
//!
//! # The empty-caps constraint (proven design)
//! The hardened `rustynetd.service` runs with `CapabilityBoundingSet=` /
//! `AmbientCapabilities=` empty (the service-hardening verifier requires this),
//! so the daemon cannot bind the privileged port 53. The resolver therefore
//! stays on its unprivileged loopback `dns_resolver_bind_addr` (default
//! `127.0.0.1:53535`) and an nft `redirect` rule maps loopback `:53` →
//! `:53535`. This was PROVEN live on `debian-headless-1`: with the redirect
//! installed, a UDP DNS query to `127.0.0.1:53` was answered by the resolver
//! listening on `127.0.0.1:53535`.
//!
//! # What this module provides
//! Pure, side-effect-free builders for the exact argv vectors and file contents
//! the protected-mode apply/teardown needs, so every privileged step stays
//! argv-only and unit-testable. No I/O, no privilege, no OS gating.
//!
//! # Remaining wiring — NOT yet done (must be a careful, reviewed change)
//! 1. **Privileged-helper validation** (`privileged_helper.rs`): add exact arms
//!    to `validate_nft_add_chain_args` + `validate_nft_add_rule_args` for the
//!    `dns_redirect` `nat`/`redirect` chain+rule produced here, and add a
//!    tightly-constrained file-write capability for the two fixed paths
//!    ([`RESOLV_CONF_PATH`], [`NETWORK_MANAGER_DNS_DROPIN_PATH`]) accepting only
//!    the fixed contents below — never arbitrary writes. Add EXHAUSTIVE negative
//!    tests proving nothing else is permitted (the helper is the privileged
//!    boundary).
//! 2. **Apply/teardown wiring** (dataplane reconcile): on protected-mode entry,
//!    install the redirect, back up & rewrite resolv.conf, write the NM drop-in;
//!    on teardown restore both files and delete the table. Tie to the killswitch
//!    lifecycle so DNS protection rolls back together.
//! 3. **Validator interaction**: the redirect table is named
//!    `rustynet_g<gen>_dns` so `is_owned_nft_table_token` already permits
//!    add/delete and the cleanup sweep removes it — but confirm
//!    [`crate::linux_runtime_nftables`] / [`crate::linux_killswitch_boot`] treat
//!    it as a benign owned table (forensic-recorded, not a failure) so the
//!    RuntimeAcls verifier does not regress. If it does, give the DNS table a
//!    distinct name and extend both allowlists in lockstep.
//! 4. **Windows NRPT parity** for the Windows dataplane.

use std::net::Ipv4Addr;

/// Loopback address `/etc/resolv.conf` points at in protected mode. The nft
/// redirect rewrites `:53` on this address to the resolver's bind port.
pub const DNS_REDIRECT_LOOPBACK_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Reviewed `/etc/resolv.conf` path (matches `linux_dns_failclosed`).
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Path of the NetworkManager `dns=none` drop-in, so NM stops managing
/// resolv.conf and cannot reintroduce off-loopback nameservers on a link
/// change (the verifier's NM-precedence check).
pub const NETWORK_MANAGER_DNS_DROPIN_PATH: &str =
    "/etc/NetworkManager/conf.d/rustynet-dns-failclosed.conf";

/// Name of the dedicated nft table holding the loopback DNS redirect for
/// dataplane `generation`. The `rustynet_g…` prefix is intentional: the
/// privileged helper's `is_owned_nft_table_token` already permits add/delete on
/// it, and the cleanup leftover-table sweep (`/^rustynet/`) removes it.
pub fn dns_redirect_table_name(generation: u64) -> String {
    format!("rustynet_g{generation}_dns")
}

/// The ordered `nft …` argv vectors that install the loopback DNS redirect on
/// `table_name`, mapping udp+tcp `:53` on [`DNS_REDIRECT_LOOPBACK_IP`] to
/// `resolver_port`. Each vector is one helper `nft` invocation. Mirrors the
/// rule proven live on debian.
pub fn dns_redirect_nft_apply_argvs(table_name: &str, resolver_port: u16) -> Vec<Vec<String>> {
    let ip = DNS_REDIRECT_LOOPBACK_IP.to_string();
    let to = format!(":{resolver_port}");
    let redirect_rule = |proto: &str| -> Vec<String> {
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            table_name.into(),
            "dns_redirect".into(),
            "meta".into(),
            "l4proto".into(),
            proto.into(),
            "ip".into(),
            "daddr".into(),
            ip.clone(),
            proto.into(),
            "dport".into(),
            "53".into(),
            "redirect".into(),
            "to".into(),
            to.clone(),
        ]
    };
    vec![
        vec![
            "add".into(),
            "table".into(),
            "inet".into(),
            table_name.into(),
        ],
        vec![
            "add".into(),
            "chain".into(),
            "inet".into(),
            table_name.into(),
            "dns_redirect".into(),
            "{".into(),
            "type".into(),
            "nat".into(),
            "hook".into(),
            "output".into(),
            "priority".into(),
            "dstnat".into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
        redirect_rule("udp"),
        redirect_rule("tcp"),
    ]
}

/// The `nft …` argv that tears down the redirect table. Deleting the whole
/// table removes the chain + both rules in one idempotent step.
pub fn dns_redirect_nft_teardown_argv(table_name: &str) -> Vec<String> {
    vec![
        "delete".into(),
        "table".into(),
        "inet".into(),
        table_name.into(),
    ]
}

/// `/etc/resolv.conf` contents for protected mode: a single loopback nameserver
/// (the rustynet resolver, reached via the nft redirect). No off-host
/// nameserver — the floor the dns-failclosed verifier checks.
pub fn loopback_resolv_conf_contents() -> String {
    format!("# rustynet protected-mode DNS fail-closed\nnameserver {DNS_REDIRECT_LOOPBACK_IP}\n")
}

/// NetworkManager drop-in contents that stop NM managing resolv.conf, so it
/// cannot reintroduce off-loopback nameservers on a link change.
pub fn network_manager_dns_none_dropin() -> String {
    "[main]\ndns=none\n".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_name_is_generation_scoped_and_helper_owned() {
        let name = dns_redirect_table_name(1);
        assert_eq!(name, "rustynet_g1_dns");
        // Must be permitted by the privileged helper's owned-table check so the
        // add/delete commands pass without weakening the allowlist.
        assert!(
            name.starts_with("rustynet_g"),
            "DNS table must keep the rustynet_g prefix the helper already owns"
        );
    }

    #[test]
    fn apply_argvs_match_the_proven_redirect_shape() {
        let argvs = dns_redirect_nft_apply_argvs("rustynet_g1_dns", 53535);
        assert_eq!(
            argvs.len(),
            4,
            "expect: add table, add chain, udp rule, tcp rule"
        );

        // add table inet rustynet_g1_dns
        assert_eq!(argvs[0], vec!["add", "table", "inet", "rustynet_g1_dns"]);
        // nat hook output chain
        let chain = argvs[1].join(" ");
        assert!(
            chain.contains("type nat hook output priority dstnat"),
            "{chain}"
        );
        assert!(chain.contains("policy accept"), "{chain}");

        // udp redirect rule — the exact shape proven live on debian
        let udp = argvs[2].join(" ");
        assert_eq!(
            udp,
            "add rule inet rustynet_g1_dns dns_redirect meta l4proto udp ip daddr 127.0.0.1 udp dport 53 redirect to :53535"
        );
        // tcp companion (DNS falls back to TCP for large responses)
        let tcp = argvs[3].join(" ");
        assert!(tcp.contains("meta l4proto tcp"), "{tcp}");
        assert!(tcp.ends_with("tcp dport 53 redirect to :53535"), "{tcp}");

        // Every argv is an `add` verb (install-only; teardown deletes the table).
        for argv in &argvs {
            assert_eq!(argv[0].as_str(), "add", "{argv:?}");
        }
    }

    #[test]
    fn redirect_port_is_threaded_from_the_resolver_bind() {
        let argvs = dns_redirect_nft_apply_argvs("rustynet_g7_dns", 5333);
        assert!(argvs[2].join(" ").ends_with("redirect to :5333"));
        assert!(argvs[3].join(" ").ends_with("redirect to :5333"));
    }

    #[test]
    fn teardown_deletes_the_whole_table() {
        assert_eq!(
            dns_redirect_nft_teardown_argv("rustynet_g1_dns"),
            vec!["delete", "table", "inet", "rustynet_g1_dns"]
        );
    }

    #[test]
    fn resolv_conf_is_loopback_only() {
        let body = loopback_resolv_conf_contents();
        assert!(body.contains("nameserver 127.0.0.1"));
        // No off-host nameserver may appear — the fail-closed floor.
        assert!(!body.contains("1.1.1.1"));
        assert!(!body.contains("8.8.8.8"));
        // Must not point at the systemd-resolved stub (verifier rejects that
        // while systemd-resolved holds 127.0.0.53:53).
        assert!(!body.contains("127.0.0.53"));
    }

    #[test]
    fn network_manager_dropin_disables_nm_dns_management() {
        let body = network_manager_dns_none_dropin();
        assert!(body.contains("[main]"));
        assert!(body.contains("dns=none"));
    }
}
