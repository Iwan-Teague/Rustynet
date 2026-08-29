//! Linux nftables rendering for the RustyDNS tandem transparent DNS redirect
//! (D-6c). Pure rule-string generation only — no I/O, no process execution,
//! no backend types. The rendered `nft -f` text is applied through the
//! existing argv-only privileged helper, so every field is strictly validated
//! here before it is allowed into rule text.
//!
//! Design basis: `documents/operations/active/RustydnsTandemIntegrationDesign_2026-08-27.md`
//! §7.2 (transparent path) and §9.1 (Linux nft generation). The redirect is
//! ADDITIVE to the base exit NAT (`rustynet_nat_g<N>`) and base killswitch
//! (`rustynet_g<N>`): it owns two logically separate generation-scoped tables
//! and never touches the base tables:
//!
//! - `ip rustynet_tdns_nat4_g<N>` — prerouting dstnat chain translating
//!   selected clients' outbound plain DNS (udp/tcp dport 53, any destination
//!   except the service itself) to the exit-hosted rustydns :53.
//! - `inet rustynet_tdns_filter_g<N>` — forward containment: admit only
//!   post-DNAT queries (tunnel input + selected source + exact service
//!   address + port 53) and drop any selected-source port-53 forwarding that
//!   was NOT translated, so translation absence never opens a plaintext
//!   escape while the redirect is active. The SAME chain additionally
//!   carries the owner-decision-3 DoT/DoH egress block, DEFAULT-ON whenever
//!   the redirect is active: drop selected-source udp/tcp `:853` (DoT,
//!   except the sanctioned path to the mesh resolver) and drop `:443` to
//!   the pinned [`rustynet_control::tandem_dns_redirect::
//!   KNOWN_DOH_RESOLVER_IPS`] set (tcp+udp). These drops are INSEPARABLE
//!   from the redirect: same table, same generation, one teardown — no
//!   residue (§10.7).
//!
//! Contained / non-redirect phases must NOT install these tables; the pure
//! control-plane decision lives in `rustynet-control::tandem_dns_redirect`
//! and this module only renders what that decision authorized.

use rustynet_control::managed_dns_handoff::{ManagedDnsEndpoint, MeshIpv4Prefix};
use rustynet_control::tandem_dns::TandemScope;
use rustynet_control::tandem_dns_redirect::{
    KNOWN_DOH_RESOLVER_IPS, TANDEM_DNS_DOH_BLOCK_PORT, TANDEM_DNS_DOT_PORT,
    TANDEM_DNS_REDIRECT_PORT,
};
use std::net::Ipv4Addr;

/// Maximum characters accepted for a Linux interface name (kernel limit 15).
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Characters permitted inside an interface name in rendered rule text.
fn is_interface_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// Strict interface-name validation before any interpolation into rule text.
fn validate_interface_name(name: &str) -> Result<(), TandemDnsRedirectRenderError> {
    if name.is_empty() || name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(TandemDnsRedirectRenderError {
            reason: format!(
                "interface name must be 1-{MAX_INTERFACE_NAME_LEN} ascii characters, got length {}",
                name.len()
            ),
        });
    }
    if !name.chars().all(is_interface_name_char) {
        return Err(TandemDnsRedirectRenderError {
            reason: "interface name contains characters outside [A-Za-z0-9._-]".to_string(),
        });
    }
    Ok(())
}

/// Strict generation validation: generation-scoped table names carry a
/// non-zero decimal generation suffix, mirroring the base `_g<N>` convention.
fn validate_generation(generation: u32) -> Result<(), TandemDnsRedirectRenderError> {
    if generation == 0 {
        return Err(TandemDnsRedirectRenderError {
            reason: "generation must be non-zero".to_string(),
        });
    }
    Ok(())
}

/// Strict service-address validation: the DNAT target must sit inside the
/// mesh prefix so a mis-typed endpoint can never point the redirect at an
/// arbitrary off-mesh address.
fn validate_service_address(
    endpoint: &ManagedDnsEndpoint,
    mesh_prefix: Option<&MeshIpv4Prefix>,
) -> Result<Ipv4Addr, TandemDnsRedirectRenderError> {
    let address = endpoint.mesh_address();
    match mesh_prefix {
        Some(prefix) if prefix.contains(address) => Ok(address),
        _ => Err(TandemDnsRedirectRenderError {
            reason: "service address missing or outside the mesh prefix".to_string(),
        }),
    }
}

/// Parse and validate an explicit selected-source list for
/// [`TandemScope::NodeIds`]-scoped redirection. The list must be non-empty;
/// every entry must be a valid IPv4 address. Order is preserved so rendering
/// is deterministic for a given input.
fn validate_selected_sources(
    sources: &[String],
) -> Result<Vec<Ipv4Addr>, TandemDnsRedirectRenderError> {
    if sources.is_empty() {
        return Err(TandemDnsRedirectRenderError {
            reason: "explicit selected-source list must not be empty".to_string(),
        });
    }
    let mut parsed = Vec::with_capacity(sources.len());
    for source in sources {
        let addr: Ipv4Addr = source.parse().map_err(|_| TandemDnsRedirectRenderError {
            reason: format!("selected source {source:?} is not a valid IPv4 address"),
        })?;
        parsed.push(addr);
    }
    Ok(parsed)
}

/// Render error: every refusal carries a concrete reason and Display text
/// prefixed with "render refused" so a caller can never mistake a refusal for
/// an empty rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDnsRedirectRenderError {
    pub reason: String,
}

impl std::fmt::Display for TandemDnsRedirectRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "render refused: {}", self.reason)
    }
}

impl std::error::Error for TandemDnsRedirectRenderError {}

/// Fully-validated inputs for rendering one generation of the tandem DNS
/// redirect tables. Construction is fallible: every field is checked before
/// rendering can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDnsRedirectRenderInput {
    tunnel_iface: String,
    generation: u32,
    service_address: Ipv4Addr,
    selected_sources: SelectedSources,
}

/// The selected client set rendered into the rules. `AllClientsUsingExit`
/// scopes the redirect by tunnel input interface only (no explicit source
/// set); `NodeIds` carries the exact per-node mesh addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SelectedSources {
    AllClientsUsingExit,
    NodeIds(Vec<Ipv4Addr>),
}

impl TandemDnsRedirectRenderInput {
    /// Validate and build a render input. Fails closed: any invalid field
    /// refuses rendering entirely.
    pub fn new(
        tunnel_iface: &str,
        generation: u32,
        scope: &TandemScope,
        endpoint: &ManagedDnsEndpoint,
        mesh_prefix: Option<&MeshIpv4Prefix>,
    ) -> Result<Self, TandemDnsRedirectRenderError> {
        validate_interface_name(tunnel_iface)?;
        validate_generation(generation)?;
        let service_address = validate_service_address(endpoint, mesh_prefix)?;
        let selected_sources = match scope {
            TandemScope::AllClientsUsingExit => SelectedSources::AllClientsUsingExit,
            TandemScope::NodeIds(node_ids) => {
                SelectedSources::NodeIds(validate_selected_sources(node_ids)?)
            }
        };
        Ok(Self {
            tunnel_iface: tunnel_iface.to_string(),
            generation,
            service_address,
            selected_sources,
        })
    }

    fn nat_table_name(&self) -> String {
        format!("rustynet_tdns_nat4_g{}", self.generation)
    }

    fn filter_table_name(&self) -> String {
        format!("rustynet_tdns_filter_g{}", self.generation)
    }

    /// The source-matching fragment shared by the DNAT and filter rules.
    /// `AllClientsUsingExit` matches by tunnel input interface alone;
    /// `NodeIds` adds an explicit source-address set.
    fn source_match_fragment(&self) -> String {
        match &self.selected_sources {
            SelectedSources::AllClientsUsingExit => String::new(),
            SelectedSources::NodeIds(addresses) => {
                let set = addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("ip saddr {{ {set} }} ")
            }
        }
    }
}

/// Render the complete `nft -f` payload installing one generation of the
/// tandem DNS redirect: the `ip rustynet_tdns_nat4_g<N>` dstnat table and the
/// `inet rustynet_tdns_filter_g<N>` containment table in a single atomic
/// payload. Deterministic: identical inputs produce byte-identical output.
pub fn render_tandem_dns_redirect_install(input: &TandemDnsRedirectRenderInput) -> String {
    let service = input.service_address;
    let iface = &input.tunnel_iface;
    let source_match = input.source_match_fragment();
    let port = TANDEM_DNS_REDIRECT_PORT;

    let mut out = String::new();
    out.push_str("# rustynet tandem dns redirect: generation-scoped, additive to base exit NAT\n");
    out.push_str(&format!("table ip {} {{\n", input.nat_table_name()));
    out.push_str("    chain prerouting_dstnat {\n");
    out.push_str("        type nat hook prerouting priority dstnat; policy accept;\n");
    // Plain-DNS redirect: selected clients' outbound udp/tcp :53 to any
    // destination except the service itself is translated to the local
    // rustydns. The mesh source is preserved (no source rewrite here).
    for protocol in ["udp", "tcp"] {
        out.push_str(&format!(
            "        iifname \"{iface}\" {source_match}ip daddr != {service} {protocol} dport {port} dnat to {service}:{port}\n"
        ));
    }
    out.push_str("    }\n");
    out.push_str("}\n");

    out.push_str(&format!("table inet {} {{\n", input.filter_table_name()));
    out.push_str("    chain forward_dns_containment {\n");
    out.push_str("        type filter hook forward priority 0; policy accept;\n");
    // Admission: post-DNAT queries (tunnel input, selected source, exact
    // service address, port 53) are accepted.
    for protocol in ["udp", "tcp"] {
        out.push_str(&format!(
            "        iifname \"{iface}\" {source_match}ip daddr {service} {protocol} dport {port} accept\n"
        ));
    }
    // Containment: any selected-source port-53 forwarding that was NOT
    // translated is dropped, so translation absence never opens a plaintext
    // escape while the redirect is active.
    for protocol in ["udp", "tcp"] {
        out.push_str(&format!(
            "        iifname \"{iface}\" {source_match}ip daddr != {service} {protocol} dport {port} drop\n"
        ));
    }
    // DoT egress block (owner decision 3, default-on): selected sources may
    // not bypass the redirect via DNS-over-TLS. The mesh resolver itself is
    // exempt (the sanctioned tunnel path), mirroring the :53 loop guard.
    for protocol in ["udp", "tcp"] {
        out.push_str(&format!(
            "        iifname \"{iface}\" {source_match}ip daddr != {service} {protocol} dport {dot} drop\n",
            dot = TANDEM_DNS_DOT_PORT,
        ));
    }
    // Known-DoH-endpoint block (owner decision 3, default-on): the pinned,
    // versioned public-resolver set on :443 (tcp and udp — the latter covers
    // HTTP/3 DoH; fail-closed prefers the closed-direction error). KNOWN
    // MECHANISM LIMIT: DoH-over-:443 to an arbitrary host is indistinguish-
    // able from HTTPS without SNI inspection and is a documented residual
    // owned by an SNI-inspection follow-up, not an open door left by choice.
    for ip in KNOWN_DOH_RESOLVER_IPS {
        for protocol in ["tcp", "udp"] {
            out.push_str(&format!(
                "        iifname \"{iface}\" {source_match}ip daddr {ip} {protocol} dport {doh} drop\n",
                doh = TANDEM_DNS_DOH_BLOCK_PORT,
            ));
        }
    }
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// Render the exact teardown payload for one generation: deleting the two
/// tandem-owned tables and NOTHING else. Base exit NAT (`rustynet_nat_g<N>`)
/// and base killswitch (`rustynet_g<N>`) tables are never referenced, so
/// teardown cannot leave redirect residue nor damage base posture.
pub fn render_tandem_dns_redirect_teardown(
    generation: u32,
) -> Result<String, TandemDnsRedirectRenderError> {
    validate_generation(generation)?;
    Ok(format!(
        "delete table ip rustynet_tdns_nat4_g{generation}\ndelete table inet rustynet_tdns_filter_g{generation}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESH_PREFIX: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
    const SERVICE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 7);

    fn endpoint() -> ManagedDnsEndpoint {
        ManagedDnsEndpoint::new(SERVICE)
    }

    fn mesh_prefix() -> Option<MeshIpv4Prefix> {
        Some(MeshIpv4Prefix::new(MESH_PREFIX, 10).unwrap())
    }

    fn all_clients_input() -> TandemDnsRedirectRenderInput {
        TandemDnsRedirectRenderInput::new(
            "utun9",
            3,
            &TandemScope::AllClientsUsingExit,
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap()
    }

    fn node_ids_input() -> TandemDnsRedirectRenderInput {
        TandemDnsRedirectRenderInput::new(
            "utun9",
            3,
            &TandemScope::NodeIds(vec!["100.64.0.11".to_string(), "100.64.0.12".to_string()]),
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap()
    }

    #[test]
    fn install_is_deterministic_and_generation_scoped() {
        let first = render_tandem_dns_redirect_install(&all_clients_input());
        let second = render_tandem_dns_redirect_install(&all_clients_input());
        assert_eq!(first, second);
        assert!(first.contains("table ip rustynet_tdns_nat4_g3 {"));
        assert!(first.contains("table inet rustynet_tdns_filter_g3 {"));
        assert!(!first.contains("rustynet_nat_g"));
        assert!(!first.contains("table rustynet_g"));
    }

    #[test]
    fn install_redirects_port_53_to_service_and_preserves_source() {
        let rendered = render_tandem_dns_redirect_install(&all_clients_input());
        assert!(rendered.contains(
            "iifname \"utun9\" ip daddr != 100.64.0.7 udp dport 53 dnat to 100.64.0.7:53"
        ));
        assert!(rendered.contains(
            "iifname \"utun9\" ip daddr != 100.64.0.7 tcp dport 53 dnat to 100.64.0.7:53"
        ));
        assert!(rendered.contains("type nat hook prerouting priority dstnat;"));
        // Mesh source preserved: no masquerade / source rewrite in the
        // redirect tables.
        assert!(!rendered.contains("masquerade"));
    }

    #[test]
    fn all_clients_scope_matches_by_tunnel_iface_only() {
        let rendered = render_tandem_dns_redirect_install(&all_clients_input());
        assert!(!rendered.contains("ip saddr {"));
    }

    #[test]
    fn node_ids_scope_renders_explicit_source_set() {
        let rendered = render_tandem_dns_redirect_install(&node_ids_input());
        assert!(rendered.contains("ip saddr { 100.64.0.11, 100.64.0.12 } "));
        // The explicit set must appear on EVERY rule: 2 DNAT + 2 port-53
        // admission + 2 port-53 drop + 2 DoT drop + 16 DoH drops (8 pinned
        // IPs x tcp/udp) = 24.
        assert_eq!(
            rendered
                .matches("ip saddr { 100.64.0.11, 100.64.0.12 } ")
                .count(),
            24
        );
    }

    #[test]
    fn filter_containment_drops_untranslated_port_53() {
        let rendered = render_tandem_dns_redirect_install(&all_clients_input());
        assert!(rendered.contains("iifname \"utun9\" ip daddr 100.64.0.7 udp dport 53 accept"));
        assert!(rendered.contains("iifname \"utun9\" ip daddr != 100.64.0.7 udp dport 53 drop"));
        assert!(rendered.contains("type filter hook forward priority 0;"));
    }

    /// Owner decision 3: the DoT/DoH egress block is DEFAULT-ON and rendered
    /// into the SAME generation-scoped filter table as the :53 redirect.
    #[test]
    fn dot_and_doh_blocks_render_in_the_generation_scoped_filter_table() {
        let rendered = render_tandem_dns_redirect_install(&all_clients_input());
        // DoT: udp+tcp :853, mesh resolver exempt.
        assert!(rendered.contains("iifname \"utun9\" ip daddr != 100.64.0.7 udp dport 853 drop"));
        assert!(rendered.contains("iifname \"utun9\" ip daddr != 100.64.0.7 tcp dport 853 drop"));
        // DoH: every pinned IP on :443, tcp AND udp (HTTP/3 covered).
        for ip in KNOWN_DOH_RESOLVER_IPS {
            assert!(rendered.contains(&format!(
                "iifname \"utun9\" ip daddr {ip} tcp dport 443 drop"
            )));
            assert!(rendered.contains(&format!(
                "iifname \"utun9\" ip daddr {ip} udp dport 443 drop"
            )));
        }
        // The :443 block is scoped to the pinned set only: exactly
        // 2 x |pinned| drop lines name :443, nothing broader.
        assert_eq!(
            rendered
                .lines()
                .filter(|l| l.contains("dport 443 drop"))
                .count(),
            KNOWN_DOH_RESOLVER_IPS.len() * 2
        );
        // DoT/DoH never appears in the dstnat (translation) table.
        let nat_half = rendered.split("table inet ").next().unwrap_or_default();
        assert!(!nat_half.contains("dport 853"));
        assert!(!nat_half.contains("dport 443"));
    }

    /// §10.7 teardown-together: the DoT/DoH drops live ONLY inside the two
    /// tandem-owned tables, so the existing two-line table deletion removes
    /// them together with the :53 redirect — nothing else to clean up.
    #[test]
    fn teardown_removes_dot_and_doh_drops_together_with_the_redirect() {
        let install = render_tandem_dns_redirect_install(&all_clients_input());
        let teardown = render_tandem_dns_redirect_teardown(3).unwrap();
        // Every rule (including DoT/DoH) is inside a tdns table.
        for line in install.lines() {
            assert!(
                !line.contains("dport 853") && !line.contains("dport 443")
                    || install.contains("rustynet_tdns_filter_g3"),
                "DoT/DoH drop outside the generation-scoped tandem table: {line}"
            );
        }
        assert_eq!(
            teardown,
            "delete table ip rustynet_tdns_nat4_g3\ndelete table inet rustynet_tdns_filter_g3\n"
        );
        // No additional DoT/DoH-specific teardown statement exists.
        assert!(!teardown.contains("853"));
        assert!(!teardown.contains("443"));
    }

    #[test]
    fn teardown_removes_exactly_the_two_tandem_tables() {
        let rendered = render_tandem_dns_redirect_teardown(3).unwrap();
        assert_eq!(
            rendered,
            "delete table ip rustynet_tdns_nat4_g3\ndelete table inet rustynet_tdns_filter_g3\n"
        );
        // No base table is ever referenced by teardown.
        assert!(!rendered.contains("rustynet_nat_g"));
        assert!(!rendered.contains("rustynet_g"));
    }

    #[test]
    fn validation_refuses_bad_inputs() {
        // Generation zero.
        let err = TandemDnsRedirectRenderInput::new(
            "utun9",
            0,
            &TandemScope::AllClientsUsingExit,
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "render refused: generation must be non-zero"
        );
        // Bad interface name.
        assert!(
            TandemDnsRedirectRenderInput::new(
                "bad iface!",
                3,
                &TandemScope::AllClientsUsingExit,
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Over-long interface name.
        assert!(
            TandemDnsRedirectRenderInput::new(
                "aaaaaaaaaaaaaaaa",
                3,
                &TandemScope::AllClientsUsingExit,
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Empty explicit source list.
        assert!(
            TandemDnsRedirectRenderInput::new(
                "utun9",
                3,
                &TandemScope::NodeIds(vec![]),
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Invalid source address.
        assert!(
            TandemDnsRedirectRenderInput::new(
                "utun9",
                3,
                &TandemScope::NodeIds(vec!["not-an-ip".to_string()]),
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Missing mesh prefix (fail-closed: cannot prove service in mesh).
        assert!(
            TandemDnsRedirectRenderInput::new(
                "utun9",
                3,
                &TandemScope::AllClientsUsingExit,
                &endpoint(),
                None
            )
            .is_err()
        );
        // Service address outside the mesh prefix.
        let off_mesh = ManagedDnsEndpoint::new(Ipv4Addr::new(192, 0, 2, 9));
        assert!(
            TandemDnsRedirectRenderInput::new(
                "utun9",
                3,
                &TandemScope::AllClientsUsingExit,
                &off_mesh,
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Teardown of generation zero refuses.
        assert!(render_tandem_dns_redirect_teardown(0).is_err());
    }

    #[test]
    fn different_generations_never_collide() {
        let g3 = render_tandem_dns_redirect_install(&all_clients_input());
        let g4 = TandemDnsRedirectRenderInput::new(
            "utun9",
            4,
            &TandemScope::AllClientsUsingExit,
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap();
        let g4_rendered = render_tandem_dns_redirect_install(&g4);
        assert!(g3.contains("rustynet_tdns_nat4_g3"));
        assert!(g4_rendered.contains("rustynet_tdns_nat4_g4"));
        assert!(!g4_rendered.contains("rustynet_tdns_nat4_g3"));
        assert!(!g3.contains("rustynet_tdns_nat4_g4"));
    }
}
