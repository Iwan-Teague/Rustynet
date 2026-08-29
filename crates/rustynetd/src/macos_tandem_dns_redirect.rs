//! macOS `pf` rendering for the RustyDNS tandem transparent DNS redirect
//! (D-6c). Pure rule-string generation only — no I/O, no process execution,
//! no backend types. The rendered rules load through the existing
//! regeneration-style `macos-pf-load` privileged builtin: the daemon sends a
//! validated structured spec and the helper re-renders this exact text,
//! derives the anchor name itself, and owns the temp file + `pfctl`
//! invocation, so the daemon can never inject rule text or redirect a load.
//!
//! Design basis: `documents/operations/active/RustydnsTandemIntegrationDesign_2026-08-27.md`
//! §7.2 (transparent path) and §9.2 (macOS pf generation). The redirect is
//! ADDITIVE to the base exit NAT (`com.rustynet/nat`) and the base killswitch
//! (`com.apple/rustynet_g<N>`): it owns one logically separate
//! generation-scoped translation+filter anchor and never touches the base
//! anchors:
//!
//! - `com.rustynet/tdns_g<N>` — the tandem anchor holding ONLY the reviewed
//!   `rdr` translation forms (selected clients' outbound plain DNS,
//!   udp/tcp dport 53, any destination except the service itself, translated
//!   to the exit-hosted rustydns :53) plus the tandem containment filter:
//!   admit only post-translation queries (tunnel input + selected source +
//!   exact service address + port 53) and drop any selected-source port-53
//!   input that was NOT translated, so translation absence never opens a
//!   plaintext escape while the redirect is active.
//!
//! The terminal `block drop out quick all` stays in the killswitch anchor;
//! the tandem anchor never relaxes base egress posture.
//!
//! Contained / non-redirect phases must NOT install this anchor; the pure
//! control-plane decision lives in `rustynet-control::tandem_dns_redirect`
//! and this module only renders what that decision authorized.

use rustynet_control::managed_dns_handoff::{ManagedDnsEndpoint, MeshIpv4Prefix};
use rustynet_control::tandem_dns::TandemScope;
use rustynet_control::tandem_dns_redirect::{TANDEM_DNS_REDIRECT_PORT, TandemDnsRedirectDecision};
use std::net::Ipv4Addr;

/// Prefix of the generation-scoped tandem anchor name. The full name is
/// `{prefix}{generation}` (e.g. `com.rustynet/tdns_g3`), mirroring the
/// killswitch `com.apple/rustynet_g<N>` convention. It is disjoint from the
/// base exit NAT anchor (`com.rustynet/nat`), the base killswitch anchors
/// (`com.apple/rustynet_g*`), and the blind-exit anchor
/// (`com.rustynet/blind_exit`).
pub const MACOS_TANDEM_DNS_PF_ANCHOR_PREFIX: &str = "com.rustynet/tdns_g";

/// Maximum characters accepted for a `pf` interface name (matches the
/// `macos_pf_load_spec::parse_interface` posture).
const MAX_INTERFACE_NAME_LEN: usize = 31;

/// The `pfctl -s` subcommand that dumps the translation (rdr) ruleset.
pub const PF_TRANSLATION_DUMP_ARG: &str = "nat";

/// The `pfctl -s` subcommand that dumps the filter ruleset.
pub const PF_FILTER_DUMP_ARG: &str = "rules";

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

/// Strict generation validation: the generation-scoped anchor name carries a
/// non-zero decimal generation suffix, mirroring the base `_g<N>` convention.
fn validate_generation(generation: u64) -> Result<(), TandemDnsRedirectRenderError> {
    if generation == 0 {
        return Err(TandemDnsRedirectRenderError {
            reason: "generation must be non-zero".to_string(),
        });
    }
    Ok(())
}

/// Strict service-address validation: the rdr target must sit inside the mesh
/// prefix so a mis-typed endpoint can never point the redirect at an
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

/// The anchor name for one generation of the tandem DNS redirect anchor.
/// Fails closed on a zero generation (an unprovisioned generation must never
/// resolve to a shared/implicit anchor).
pub fn macos_tandem_dns_pf_anchor_name(
    generation: u64,
) -> Result<String, TandemDnsRedirectRenderError> {
    validate_generation(generation)?;
    Ok(format!("{MACOS_TANDEM_DNS_PF_ANCHOR_PREFIX}{generation}"))
}

/// The exact `pfctl` argument vector that tears down one generation of the
/// tandem anchor: flushing the tandem anchor BY REFERENCE and nothing else.
/// No base anchor (`com.rustynet/nat`, `com.apple/rustynet_g*`,
/// `com.rustynet/blind_exit`) is ever referenced, so teardown cannot leave
/// redirect residue nor damage base posture.
pub fn macos_tandem_dns_teardown_args(
    generation: u64,
) -> Result<Vec<String>, TandemDnsRedirectRenderError> {
    let anchor = macos_tandem_dns_pf_anchor_name(generation)?;
    Ok(vec![
        "-a".to_owned(),
        anchor,
        "-F".to_owned(),
        "all".to_owned(),
    ])
}

/// Fully-validated parameters for rendering one generation of the tandem DNS
/// redirect anchor. Construction is fallible: every field is checked before
/// rendering can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosTandemDnsRedirectPfConfig {
    tunnel_interface: String,
    generation: u64,
    service_address: Ipv4Addr,
    /// Empty means [`TandemScope::AllClientsUsingExit`] (the redirect is
    /// scoped by tunnel input interface only); non-empty is the exact
    /// [`TandemScope::NodeIds`] mesh-address set.
    selected_sources: Vec<Ipv4Addr>,
    /// The signed mesh prefix the service address was proven to sit inside.
    /// Carried so a decoded (helper-side) spec can re-prove containment.
    mesh_prefix: MeshIpv4Prefix,
    anchor_name: String,
}

impl MacosTandemDnsRedirectPfConfig {
    /// Validate and build the config. Fails closed: any invalid field refuses
    /// rendering entirely.
    pub fn new(
        tunnel_interface: &str,
        generation: u64,
        scope: &TandemScope,
        endpoint: &ManagedDnsEndpoint,
        mesh_prefix: Option<&MeshIpv4Prefix>,
    ) -> Result<Self, TandemDnsRedirectRenderError> {
        validate_interface_name(tunnel_interface)?;
        validate_generation(generation)?;
        let service_address = validate_service_address(endpoint, mesh_prefix)?;
        let selected_sources = match scope {
            TandemScope::AllClientsUsingExit => Vec::new(),
            TandemScope::NodeIds(node_ids) => validate_selected_sources(node_ids)?,
        };
        let mesh_prefix = *mesh_prefix.ok_or_else(|| TandemDnsRedirectRenderError {
            reason: "mesh prefix missing".to_string(),
        })?;
        let anchor_name = macos_tandem_dns_pf_anchor_name(generation)?;
        Ok(Self {
            tunnel_interface: tunnel_interface.to_string(),
            generation,
            service_address,
            selected_sources,
            mesh_prefix,
            anchor_name,
        })
    }

    /// Bridge from the pure control-plane decision: ONLY a
    /// [`TandemDnsRedirectDecision::Redirect`] proceeds to rendering.
    /// `NoRedirect` and `ContainNoRedirect` refuse here, so a contained or
    /// inactive tandem phase can never install a redirect rule — the base
    /// DNS-fail-closed posture remains the only DNS behavior.
    pub fn from_redirect_decision(
        tunnel_interface: &str,
        generation: u64,
        decision: &TandemDnsRedirectDecision,
        mesh_prefix: Option<&MeshIpv4Prefix>,
    ) -> Result<Self, TandemDnsRedirectRenderError> {
        match decision {
            TandemDnsRedirectDecision::Redirect {
                scope,
                service_address,
                ..
            } => Self::new(
                tunnel_interface,
                generation,
                scope,
                &ManagedDnsEndpoint::new(*service_address),
                mesh_prefix,
            ),
            TandemDnsRedirectDecision::NoRedirect { .. } => Err(TandemDnsRedirectRenderError {
                reason: "decision is NoRedirect: plain DNS stays blocked by the base \
                             fail-closed posture and no redirect rule may be installed"
                    .to_string(),
            }),
            TandemDnsRedirectDecision::ContainNoRedirect { .. } => {
                Err(TandemDnsRedirectRenderError {
                    reason: "decision is ContainNoRedirect: containment is active and no \
                             redirect rule may be installed"
                        .to_string(),
                })
            }
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn anchor_name(&self) -> &str {
        &self.anchor_name
    }

    pub fn tunnel_interface(&self) -> &str {
        &self.tunnel_interface
    }

    pub fn service_address(&self) -> Ipv4Addr {
        self.service_address
    }

    /// The selected-source set: `None` = all clients using this exit
    /// (interface-scoped), `Some` = the exact per-node mesh addresses.
    pub fn selected_sources(&self) -> Option<&[Ipv4Addr]> {
        if self.selected_sources.is_empty() {
            None
        } else {
            Some(&self.selected_sources)
        }
    }

    pub fn mesh_prefix(&self) -> &MeshIpv4Prefix {
        &self.mesh_prefix
    }

    /// The `from` fragment shared by the rdr and filter rules.
    /// `AllClientsUsingExit` matches by tunnel input interface alone
    /// (`from any`); `NodeIds` restricts to the explicit source set.
    fn source_match_fragment(&self) -> String {
        match self.selected_sources() {
            None => "from any ".to_owned(),
            Some(addresses) => {
                let set = addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("from {{ {set} }} ")
            }
        }
    }

    /// One rdr line per protocol. The `!` address negation mirrors the Linux
    /// `ip daddr != <service>` loop guard: a query already addressed to the
    /// service itself is never re-translated (which would loop), and it is
    /// admitted by the pass-in filter rule instead.
    fn rdr_rule(&self, protocol: &str) -> String {
        format!(
            "rdr on {iface} inet proto {protocol} {source_match}to ! {service} port {port} -> {service} port {port}",
            iface = self.tunnel_interface,
            source_match = self.source_match_fragment(),
            service = self.service_address,
            port = TANDEM_DNS_REDIRECT_PORT,
        )
    }

    /// Admission filter rule: post-translation queries (tunnel input,
    /// selected source, exact service address, port 53) are accepted.
    fn pass_in_rule(&self, protocol: &str) -> String {
        format!(
            "pass in quick on {iface} inet proto {protocol} {source_match}to {service} port {port} keep state",
            iface = self.tunnel_interface,
            source_match = self.source_match_fragment(),
            service = self.service_address,
            port = TANDEM_DNS_REDIRECT_PORT,
        )
    }

    /// Containment filter rule: any selected-source port-53 input that was
    /// NOT translated is dropped, so translation absence never opens a
    /// plaintext escape while the redirect is active.
    fn block_in_rule(&self, protocol: &str) -> String {
        format!(
            "block drop in quick on {iface} inet proto {protocol} {source_match}to any port {port} label \"rustynet-tdns-contain-{protocol}\"",
            iface = self.tunnel_interface,
            source_match = self.source_match_fragment(),
            port = TANDEM_DNS_REDIRECT_PORT,
        )
    }

    fn all_rules(&self) -> Vec<String> {
        let mut rules = Vec::with_capacity(6);
        for protocol in ["udp", "tcp"] {
            rules.push(self.rdr_rule(protocol));
        }
        for protocol in ["udp", "tcp"] {
            rules.push(self.pass_in_rule(protocol));
        }
        for protocol in ["udp", "tcp"] {
            rules.push(self.block_in_rule(protocol));
        }
        rules
    }
}

/// Render the complete `pf` ruleset loading one generation of the tandem DNS
/// redirect anchor: the reviewed rdr translation forms followed by the
/// containment filter rules, in a single deterministic payload. Identical
/// inputs produce byte-identical output.
pub fn build_macos_tandem_dns_redirect_pf_rules(config: &MacosTandemDnsRedirectPfConfig) -> String {
    let mut out = String::new();
    for rule in config.all_rules() {
        out.push_str(&rule);
        out.push('\n');
    }
    out
}

/// Canonicalize a live (`pfctl -s nat` / `pfctl -s rules`) or rendered rule
/// line for exact-set comparison: trimmed, whitespace-collapsed, lowercased,
/// with the two forms pfctl is known to normalize folded onto the rendered
/// form (`port = 53` → `port 53`, and the negated-address dump form
/// `!= addr` → `! addr`). Folding is idempotent so rendered text compares
/// equal to itself and to its dump.
fn normalize_pf_rule_line(line: &str) -> String {
    let trimmed = line.trim().to_ascii_lowercase();
    let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.replace("port = ", "port ").replace(" != ", " ! ")
}

/// Verify the LIVE translation ruleset of the tandem anchor (from
/// `pfctl -a <anchor> -s nat`): every line must be exactly a reviewed rdr
/// form for this config — none missing, nothing extra. Returns the list of
/// reasons (empty = verified).
pub fn evaluate_macos_tandem_dns_redirect_translation(
    live_rules: &str,
    config: &MacosTandemDnsRedirectPfConfig,
) -> Vec<String> {
    let expected: Vec<String> = ["udp", "tcp"]
        .iter()
        .map(|p| normalize_pf_rule_line(&config.rdr_rule(p)))
        .collect();
    evaluate_against_expected(live_rules, &expected, "translation")
}

/// Verify the LIVE filter ruleset of the tandem anchor (from
/// `pfctl -a <anchor> -s rules`): every line must be exactly a reviewed
/// pass-in containment form or block-in containment form for this config.
/// Returns the list of reasons (empty = verified).
pub fn evaluate_macos_tandem_dns_redirect_filter(
    live_rules: &str,
    config: &MacosTandemDnsRedirectPfConfig,
) -> Vec<String> {
    let expected: Vec<String> = ["udp", "tcp"]
        .iter()
        .flat_map(|p| {
            vec![
                normalize_pf_rule_line(&config.pass_in_rule(p)),
                normalize_pf_rule_line(&config.block_in_rule(p)),
            ]
        })
        .collect();
    evaluate_against_expected(live_rules, &expected, "filter")
}

/// Shared exact-set evaluator: the live ruleset must be non-empty and every
/// line must normalize onto one expected reviewed form. Any unreviewed line
/// or a missing expected form is a reason to refuse the load as verified.
fn evaluate_against_expected(live_rules: &str, expected: &[String], label: &str) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut seen = vec![false; expected.len()];
    let mut line_count = 0usize;
    for line in live_rules.lines() {
        if line.trim().is_empty() {
            continue;
        }
        line_count += 1;
        if line.to_ascii_lowercase().contains(" route-to ")
            || line.to_ascii_lowercase().contains(" reply-to ")
            || line.to_ascii_lowercase().contains(" dup-to ")
        {
            reasons.push(format!(
                "{label} ruleset contains a forbidden route primitive: {line}"
            ));
            continue;
        }
        let normalized = normalize_pf_rule_line(line);
        match expected.iter().position(|want| *want == normalized) {
            Some(index) => seen[index] = true,
            None => reasons.push(format!(
                "{label} ruleset contains an unreviewed rule: {line}"
            )),
        }
    }
    if line_count == 0 {
        reasons.push(format!("{label} ruleset is empty"));
    }
    for (index, want) in expected.iter().enumerate() {
        if !seen[index] {
            reasons.push(format!("{label} ruleset is missing expected rule: {want}"));
        }
    }
    reasons
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
        MeshIpv4Prefix::new(MESH_PREFIX, 10)
    }

    fn all_clients_config() -> MacosTandemDnsRedirectPfConfig {
        MacosTandemDnsRedirectPfConfig::new(
            "utun9",
            3,
            &TandemScope::AllClientsUsingExit,
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap()
    }

    fn node_ids_config() -> MacosTandemDnsRedirectPfConfig {
        MacosTandemDnsRedirectPfConfig::new(
            "utun9",
            3,
            &TandemScope::NodeIds(vec!["100.64.0.11".to_string(), "100.64.0.12".to_string()]),
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap()
    }

    fn redirect_decision_all_clients() -> TandemDnsRedirectDecision {
        TandemDnsRedirectDecision::Redirect {
            mode: rustynet_control::tandem_dns::TandemMode::ManagedRedirect,
            scope: TandemScope::AllClientsUsingExit,
            service_address: SERVICE,
        }
    }

    #[test]
    fn rules_are_deterministic_and_generation_scoped() {
        let first = build_macos_tandem_dns_redirect_pf_rules(&all_clients_config());
        let second = build_macos_tandem_dns_redirect_pf_rules(&all_clients_config());
        assert_eq!(first, second);
        // Six rules: rdr/pass/block x udp/tcp, deterministic order, no
        // comment or decoration — every line is a reviewed rule form.
        assert!(first.starts_with("rdr on "));
        assert_eq!(first.lines().count(), 6);
        // The anchor name is generation-scoped and disjoint from every base
        // anchor namespace.
        let anchor = all_clients_config().anchor_name().to_owned();
        assert_eq!(anchor, "com.rustynet/tdns_g3");
        assert!(!first.contains("com.rustynet/nat"));
        assert!(!first.contains("com.apple/rustynet_g"));
        assert!(!first.contains("com.rustynet/blind_exit"));
        assert!(
            macos_tandem_dns_pf_anchor_name(4)
                .unwrap()
                .ends_with("tdns_g4")
        );
    }

    #[test]
    fn rdr_translates_port_53_to_service_with_loop_guard() {
        let rules = build_macos_tandem_dns_redirect_pf_rules(&all_clients_config());
        assert!(rules.contains(
            "rdr on utun9 inet proto udp from any to ! 100.64.0.7 port 53 -> 100.64.0.7 port 53"
        ));
        assert!(rules.contains(
            "rdr on utun9 inet proto tcp from any to ! 100.64.0.7 port 53 -> 100.64.0.7 port 53"
        ));
    }

    #[test]
    fn all_clients_scope_matches_by_tunnel_iface_only() {
        let rules = build_macos_tandem_dns_redirect_pf_rules(&all_clients_config());
        assert!(rules.contains("from any "));
        assert!(!rules.contains("from { "));
    }

    #[test]
    fn node_ids_scope_renders_explicit_source_set_on_every_rule() {
        let rules = build_macos_tandem_dns_redirect_pf_rules(&node_ids_config());
        let fragment = "from { 100.64.0.11, 100.64.0.12 } ";
        // The explicit set must appear on all six rules (2 rdr + 2 pass +
        // 2 block), never just on the translation half.
        assert_eq!(rules.matches(fragment).count(), 6);
        assert!(rules.contains(&format!(
            "rdr on utun9 inet proto udp {fragment}to ! 100.64.0.7 port 53 -> 100.64.0.7 port 53"
        )));
        assert!(rules.contains(&format!(
            "pass in quick on utun9 inet proto udp {fragment}to 100.64.0.7 port 53 keep state"
        )));
        assert!(rules.contains(&format!(
            "block drop in quick on utun9 inet proto udp {fragment}to any port 53 label \"rustynet-tdns-contain-udp\""
        )));
    }

    #[test]
    fn filter_containment_admits_translated_and_drops_the_rest() {
        let rules = build_macos_tandem_dns_redirect_pf_rules(&all_clients_config());
        assert!(rules.contains(
            "pass in quick on utun9 inet proto udp from any to 100.64.0.7 port 53 keep state"
        ));
        assert!(rules.contains(
            "pass in quick on utun9 inet proto tcp from any to 100.64.0.7 port 53 keep state"
        ));
        assert!(rules.contains(
            "block drop in quick on utun9 inet proto udp from any to any port 53 label \"rustynet-tdns-contain-udp\""
        ));
        assert!(rules.contains(
            "block drop in quick on utun9 inet proto tcp from any to any port 53 label \"rustynet-tdns-contain-tcp\""
        ));
        // No broad pass and no nat primitive: only rdr translation.
        assert!(!rules.contains("pass in quick on utun9 all"));
        assert!(!rules.contains("\nnat "));
        assert!(!rules.starts_with("nat "));
    }

    #[test]
    fn teardown_args_flush_exactly_the_tandem_anchor() {
        let args = macos_tandem_dns_teardown_args(3).unwrap();
        assert_eq!(args, vec!["-a", "com.rustynet/tdns_g3", "-F", "all"]);
        let joined = args.join(" ");
        assert!(!joined.contains("com.rustynet/nat"));
        assert!(!joined.contains("com.apple/rustynet_g"));
        assert!(!joined.contains("blind_exit"));
        // Different generations target different anchors.
        assert_ne!(
            macos_tandem_dns_teardown_args(3).unwrap(),
            macos_tandem_dns_teardown_args(4).unwrap()
        );
        assert!(macos_tandem_dns_teardown_args(0).is_err());
    }

    #[test]
    fn validation_refuses_bad_inputs() {
        // Generation zero.
        let err = MacosTandemDnsRedirectPfConfig::new(
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
        // Bad interface name (space, then over-long).
        assert!(
            MacosTandemDnsRedirectPfConfig::new(
                "bad iface!",
                3,
                &TandemScope::AllClientsUsingExit,
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        assert!(
            MacosTandemDnsRedirectPfConfig::new(
                &"a".repeat(32),
                3,
                &TandemScope::AllClientsUsingExit,
                &endpoint(),
                mesh_prefix().as_ref()
            )
            .is_err()
        );
        // Empty explicit source list.
        assert!(
            MacosTandemDnsRedirectPfConfig::new(
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
            MacosTandemDnsRedirectPfConfig::new(
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
            MacosTandemDnsRedirectPfConfig::new(
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
            MacosTandemDnsRedirectPfConfig::new(
                "utun9",
                3,
                &TandemScope::AllClientsUsingExit,
                &off_mesh,
                mesh_prefix().as_ref()
            )
            .is_err()
        );
    }

    #[test]
    fn different_generations_never_collide() {
        let g3 = all_clients_config();
        let g4 = MacosTandemDnsRedirectPfConfig::new(
            "utun9",
            4,
            &TandemScope::AllClientsUsingExit,
            &endpoint(),
            mesh_prefix().as_ref(),
        )
        .unwrap();
        assert_eq!(g3.anchor_name(), "com.rustynet/tdns_g3");
        assert_eq!(g4.anchor_name(), "com.rustynet/tdns_g4");
        let g3_rules = build_macos_tandem_dns_redirect_pf_rules(&g3);
        let g4_rules = build_macos_tandem_dns_redirect_pf_rules(&g4);
        // The rules themselves carry the interface, not the generation (the
        // anchor carries it), but the two generations must resolve to
        // distinct anchors so their rulesets never overwrite each other.
        assert_ne!(g3.anchor_name(), g4.anchor_name());
        assert_eq!(g3_rules, g4_rules);
    }

    #[test]
    fn decision_bridge_only_proceeds_on_redirect() {
        // Redirect renders.
        let config = MacosTandemDnsRedirectPfConfig::from_redirect_decision(
            "utun9",
            3,
            &redirect_decision_all_clients(),
            mesh_prefix().as_ref(),
        )
        .unwrap();
        assert_eq!(config.anchor_name(), "com.rustynet/tdns_g3");
        assert!(build_macos_tandem_dns_redirect_pf_rules(&config).contains("rdr on utun9"));

        // NoRedirect refuses: contained/off can never install a rule.
        let err = MacosTandemDnsRedirectPfConfig::from_redirect_decision(
            "utun9",
            3,
            &TandemDnsRedirectDecision::NoRedirect { reason: None },
            mesh_prefix().as_ref(),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("decision is NoRedirect: plain DNS stays blocked")
        );

        // ContainNoRedirect refuses for the same reason.
        let err = MacosTandemDnsRedirectPfConfig::from_redirect_decision(
            "utun9",
            3,
            &TandemDnsRedirectDecision::ContainNoRedirect {
                reason: rustynet_control::tandem_dns::TandemReasonCode::Residue,
            },
            mesh_prefix().as_ref(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("decision is ContainNoRedirect"));
    }

    #[test]
    fn translation_evaluator_accepts_rendered_text_and_rejects_tamper() {
        let config = all_clients_config();
        let rules = build_macos_tandem_dns_redirect_pf_rules(&config);
        // Full ruleset against the translation evaluator would flag the
        // filter lines; the translation evaluator sees only the NAT dump,
        // so feed it the two rdr lines as pfctl would dump them.
        let rdr_only = rules
            .lines()
            .filter(|l| l.starts_with("rdr "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(evaluate_macos_tandem_dns_redirect_translation(&rdr_only, &config).is_empty());
        // pfctl-normalized forms (`port = 53`) must also verify.
        let normalized = rdr_only.replace("port 53", "port = 53");
        assert!(evaluate_macos_tandem_dns_redirect_translation(&normalized, &config).is_empty());

        // Empty dump refuses.
        assert!(!evaluate_macos_tandem_dns_redirect_translation("", &config).is_empty());
        // A nat primitive smuggled into the translation dump refuses.
        assert!(
            !evaluate_macos_tandem_dns_redirect_translation(
                &format!("{rdr_only}\nnat on en0 inet from any to any -> (en0)"),
                &config
            )
            .is_empty()
        );
        // A foreign rdr (wrong target address) refuses as unreviewed.
        assert!(
            !evaluate_macos_tandem_dns_redirect_translation(
                "rdr on utun9 inet proto udp from any to ! 1.2.3.4 port 53 -> 1.2.3.4 port 53",
                &config
            )
            .is_empty()
        );
        // A missing expected rdr (tcp half) refuses.
        let udp_only = rdr_only
            .lines()
            .filter(|l| l.contains("proto udp"))
            .collect::<Vec<_>>()
            .join("\n");
        let reasons = evaluate_macos_tandem_dns_redirect_translation(&udp_only, &config);
        assert!(reasons.iter().any(|r| r.contains("missing expected rule")));
    }

    #[test]
    fn filter_evaluator_accepts_rendered_text_and_rejects_tamper() {
        let config = all_clients_config();
        let rules = build_macos_tandem_dns_redirect_pf_rules(&config);
        let filter_only = rules
            .lines()
            .filter(|l| l.starts_with("pass ") || l.starts_with("block "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(evaluate_macos_tandem_dns_redirect_filter(&filter_only, &config).is_empty());
        // pfctl-normalized port form verifies too.
        let normalized = filter_only.replace("port 53", "port = 53");
        assert!(evaluate_macos_tandem_dns_redirect_filter(&normalized, &config).is_empty());

        // An unreviewed broad pass refuses.
        assert!(
            !evaluate_macos_tandem_dns_redirect_filter(
                &format!("{filter_only}\npass in quick on utun9 all"),
                &config
            )
            .is_empty()
        );
        // A route-to bypass primitive refuses.
        assert!(
            !evaluate_macos_tandem_dns_redirect_filter(
                &format!("{filter_only}\npass in quick on utun9 route-to (en0 1.2.3.4) all"),
                &config
            )
            .is_empty()
        );
        // A missing containment block refuses.
        let passes_only = filter_only
            .lines()
            .filter(|l| l.starts_with("pass "))
            .collect::<Vec<_>>()
            .join("\n");
        let reasons = evaluate_macos_tandem_dns_redirect_filter(&passes_only, &config);
        assert!(reasons.iter().any(|r| r.contains("missing expected rule")));
    }
}
