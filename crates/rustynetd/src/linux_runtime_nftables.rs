//! L2 — Linux runtime-nftables verifier (IPv6 parity + named-chain integrity).
//!
//! The Linux runtime path programs two nftables families to enforce
//! the killswitch + exit-mode + NAT contract that fail-closed depends
//! on:
//!
//! * `inet rustynet_g<N>` — the killswitch + forward chains. Covers
//!   IPv4 + IPv6 in one programmed chain set because the `inet`
//!   family is family-agnostic.
//! * `ip rustynet_nat_g<N>` — the IPv4 NAT/masquerade postrouting
//!   chain.
//!
//! The L8 boot-time verifier (see [`crate::linux_killswitch_boot`])
//! already pins the `inet` table presence + canonical chain set.
//! What L8 does NOT cover, and what this module adds, is the
//! steady-state runtime invariant:
//!
//! 1. BOTH families are programmed (not just the `inet` killswitch).
//! 2. Each family's chains exist in the reviewed set — no extras, no
//!    silent drops. Extras are a security-grade concern because a
//!    hostile or buggy operator script could insert a parallel chain
//!    that bypasses the reviewed policy.
//! 3. The IPv6-parity invariant: when `ipv6_parity_supported=true` is
//!    promoted (L7 follow-up), an `ip6 rustynet_nat_g<N>` sibling
//!    table is REQUIRED to mirror the IPv4 NAT family. Until that
//!    flip happens, the absence of `ip6` is acceptable and the
//!    evaluator surfaces it as informational state rather than
//!    drift; once the flip lands, the evaluator should be invoked
//!    with `ipv6_parity_required=true` and the absence of `ip6`
//!    becomes a hard reject.
//!
//! The evaluator is pure. Snapshots are produced by the collector
//! (Linux-only — parses `nft list ruleset` text) or synthesised by
//! callers (unit tests + the L7 follow-up that will plumb the
//! steady-state invariant into the daemon's reconcile loop).

#![allow(clippy::result_large_err)]

use serde::{Deserialize, Serialize};

/// Reviewed `inet` killswitch family name. Generation rotation is
/// applied as `<name>_g<digit>+` so the matcher accepts both the
/// canonical bare form and any rotated form.
pub const REVIEWED_INET_TABLE: &str = "rustynet";
/// Reviewed `ip` NAT family name (IPv4-only NAT family today).
pub const REVIEWED_IP_NAT_TABLE: &str = "rustynet_nat";
/// Reviewed `ip6` NAT family name. Only required when
/// `ipv6_parity_required=true` is passed to the evaluator.
pub const REVIEWED_IP6_NAT_TABLE: &str = "rustynet_nat";

/// Reviewed chain set inside `inet rustynet_g<N>`. A missing chain
/// is a hard fail-closed reason; an extra chain is also a
/// fail-closed reason because the runtime might be silently widened.
pub const REVIEWED_INET_CHAINS: &[&str] = &["killswitch", "forward"];

/// Reviewed chain set inside `ip rustynet_nat_g<N>`. NAT is a single
/// `postrouting` chain hooked at the postrouting priority for the
/// IPv4 exit-mode masquerade.
pub const REVIEWED_IP_NAT_CHAINS: &[&str] = &["postrouting"];

/// Reviewed chain set inside `ip6 rustynet_nat_g<N>` (when required).
/// Mirrors the IPv4 NAT shape for parity.
pub const REVIEWED_IP6_NAT_CHAINS: &[&str] = &["postrouting"];

/// One observed nftables table in the runtime snapshot. The collector
/// fills in the family + base name from the captured ruleset; chain
/// names are listed in source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedNftablesTable {
    /// `inet`, `ip`, `ip6`, or any other family token surfaced from
    /// the ruleset header.
    pub family: String,
    /// Canonical reviewed name (e.g. `rustynet`, `rustynet_nat`).
    /// Generation suffixes are stripped before this field is filled,
    /// so the evaluator can compare against the canonical reviewed
    /// constants without re-parsing.
    pub canonical_name: String,
    /// Chain names found inside the table block, in source order.
    pub chains: Vec<String>,
}

/// Captured snapshot of the runtime nftables state. The collector
/// produces this from `nft list ruleset` (or its argv-exec
/// equivalent); the evaluator only reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxRuntimeNftablesSnapshot {
    /// Source label for forensics — typically `"nft list ruleset"`
    /// when the collector ran successfully, or a stub label off
    /// Linux.
    pub ruleset_source: String,
    /// True iff the snapshot was produced by an actual Linux host
    /// observation. Off-Linux the field is false and the evaluator
    /// rejects with a clear platform-blocker reason.
    #[serde(default = "default_host_observable_true")]
    pub host_observable: bool,
    /// Every reviewed-shape table the collector recognised.
    /// Non-reviewed tables (other rustynet generations not currently
    /// promoted, or unrelated host tables) are NOT included here —
    /// they're considered out of scope and surfaced via
    /// `non_reviewed_tables` for forensic visibility only.
    pub reviewed_tables: Vec<ObservedNftablesTable>,
    /// Free-form list of any non-reviewed table headers the
    /// collector saw under a `rustynet_*` name. Surfaced for
    /// forensic visibility but does not contribute to the evaluator's
    /// pass/fail verdict.
    #[serde(default)]
    pub non_reviewed_rustynet_tables: Vec<String>,
}

fn default_host_observable_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxRuntimeNftablesReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: LinuxRuntimeNftablesSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Evaluator inputs distinct from the snapshot — these reflect the
/// daemon's configured posture (e.g. `ipv6_parity_supported`) rather
/// than observed runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinuxRuntimeNftablesPolicy {
    /// True iff the runtime is configured to require the IPv6 NAT
    /// sibling table (`ip6 rustynet_nat_g<N>`). When false, the
    /// absence of `ip6 rustynet_nat` is informational and does NOT
    /// fail the verdict; when true, it's a hard reject. The flip is
    /// gated by L7's `ipv6_parity_supported=true` promotion.
    pub ipv6_parity_required: bool,
}

/// Pure evaluator. Walks the snapshot and aggregates every drift
/// reason in a single pass. Returns `Vec<String>` so the caller
/// decides how to surface the failures.
pub fn evaluate_linux_runtime_nftables_snapshot(
    snapshot: &LinuxRuntimeNftablesSnapshot,
    policy: LinuxRuntimeNftablesPolicy,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();

    if !snapshot.host_observable {
        reasons.push(format!(
            "host state could not be observed via {}: \
             linux-runtime-nftables-check requires a Linux runtime host with \
             `nft` available",
            snapshot.ruleset_source
        ));
        return reasons;
    }

    let inet_table = reviewed_table(snapshot, "inet", REVIEWED_INET_TABLE);
    let ip_nat_table = reviewed_table(snapshot, "ip", REVIEWED_IP_NAT_TABLE);
    let ip6_nat_table = reviewed_table(snapshot, "ip6", REVIEWED_IP6_NAT_TABLE);

    match inet_table {
        Some(table) => {
            reasons.extend(check_chain_set(
                "inet",
                REVIEWED_INET_TABLE,
                &table.chains,
                REVIEWED_INET_CHAINS,
            ));
        }
        None => {
            reasons.push(format!(
                "reviewed killswitch family `inet {REVIEWED_INET_TABLE}` is missing from the \
                 runtime nftables ruleset; killswitch + forward chains cannot be enforced"
            ));
        }
    }

    match ip_nat_table {
        Some(table) => {
            reasons.extend(check_chain_set(
                "ip",
                REVIEWED_IP_NAT_TABLE,
                &table.chains,
                REVIEWED_IP_NAT_CHAINS,
            ));
        }
        None => {
            reasons.push(format!(
                "reviewed IPv4 NAT family `ip {REVIEWED_IP_NAT_TABLE}` is missing from the \
                 runtime nftables ruleset; exit-mode masquerade cannot be enforced"
            ));
        }
    }

    if policy.ipv6_parity_required {
        match ip6_nat_table {
            Some(table) => {
                reasons.extend(check_chain_set(
                    "ip6",
                    REVIEWED_IP6_NAT_TABLE,
                    &table.chains,
                    REVIEWED_IP6_NAT_CHAINS,
                ));
            }
            None => {
                reasons.push(format!(
                    "reviewed IPv6 NAT family `ip6 {REVIEWED_IP6_NAT_TABLE}` is missing from \
                     the runtime nftables ruleset; ipv6_parity_required=true demands the IPv6 \
                     NAT sibling table"
                ));
            }
        }
    }

    reasons
}

fn reviewed_table<'a>(
    snapshot: &'a LinuxRuntimeNftablesSnapshot,
    family: &str,
    canonical_name: &str,
) -> Option<&'a ObservedNftablesTable> {
    snapshot
        .reviewed_tables
        .iter()
        .find(|t| t.family == family && t.canonical_name == canonical_name)
}

fn check_chain_set(
    family: &str,
    canonical_name: &str,
    observed_chains: &[String],
    reviewed_chains: &[&str],
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    for required in reviewed_chains {
        if !observed_chains.iter().any(|c| c == required) {
            reasons.push(format!(
                "reviewed chain `{required}` missing from {family}/{canonical_name}"
            ));
        }
    }
    for observed in observed_chains {
        if !reviewed_chains.iter().any(|c| c == observed) {
            reasons.push(format!(
                "unexpected chain `{observed}` present in {family}/{canonical_name}; \
                 the reviewed chain set is fixed and silent drift is treated as drift"
            ));
        }
    }
    reasons
}

pub fn build_linux_runtime_nftables_report(
    snapshot: LinuxRuntimeNftablesSnapshot,
    policy: LinuxRuntimeNftablesPolicy,
) -> LinuxRuntimeNftablesReport {
    let drift_reasons = evaluate_linux_runtime_nftables_snapshot(&snapshot, policy);
    let overall_ok = drift_reasons.is_empty();
    LinuxRuntimeNftablesReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Strip the generation suffix `_g<digit>+` from a reviewed table
/// name. Returns the canonical bare name, or the input unchanged if
/// no suffix is present. Used by the collector so the evaluator can
/// compare against the canonical reviewed constants without
/// re-parsing.
pub fn strip_generation_suffix(name: &str) -> &str {
    if let Some((base, after_g)) = name.rsplit_once("_g")
        && !after_g.is_empty()
        && after_g.chars().all(|c| c.is_ascii_digit())
    {
        return base;
    }
    name
}

/// Parse `nft list ruleset` text into a runtime snapshot. Pure
/// parser — does no I/O. Exposed for unit tests so the parser can be
/// pinned against synthesised ruleset bodies without shelling out.
pub fn parse_nft_ruleset(body: &str) -> LinuxRuntimeNftablesSnapshot {
    let mut reviewed_tables: Vec<ObservedNftablesTable> = Vec::new();
    let mut non_reviewed_rustynet_tables: Vec<String> = Vec::new();

    let mut current_table: Option<ObservedNftablesTable> = None;
    let mut brace_depth: i32 = 0;

    for raw_line in body.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if current_table.is_none() {
            if let Some(table) = parse_table_header(trimmed) {
                let canonical = strip_generation_suffix(table.canonical_name.as_str()).to_owned();
                let is_rustynet =
                    canonical == REVIEWED_INET_TABLE || canonical == REVIEWED_IP_NAT_TABLE;
                let reviewed = is_rustynet
                    && ((table.family == "inet" && canonical == REVIEWED_INET_TABLE)
                        || (table.family == "ip" && canonical == REVIEWED_IP_NAT_TABLE)
                        || (table.family == "ip6" && canonical == REVIEWED_IP6_NAT_TABLE));
                if reviewed {
                    current_table = Some(ObservedNftablesTable {
                        family: table.family,
                        canonical_name: canonical,
                        chains: Vec::new(),
                    });
                    brace_depth = 1;
                } else if table.canonical_name.starts_with("rustynet")
                    || table.canonical_name.starts_with("rustynet_nat")
                {
                    non_reviewed_rustynet_tables
                        .push(format!("{} {}", table.family, table.canonical_name));
                }
            }
            continue;
        }
        // Track brace depth so we know when we leave the table.
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }
        if let Some(rest) = trimmed.strip_prefix("chain ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty()
                && let Some(t) = current_table.as_mut()
                && !t.chains.contains(&name)
            {
                t.chains.push(name);
            }
        }
        if brace_depth <= 0
            && let Some(table) = current_table.take()
        {
            reviewed_tables.push(table);
        }
    }
    if let Some(table) = current_table.take() {
        reviewed_tables.push(table);
    }

    LinuxRuntimeNftablesSnapshot {
        ruleset_source: "nft list ruleset".to_owned(),
        host_observable: true,
        reviewed_tables,
        non_reviewed_rustynet_tables,
    }
}

struct ParsedTableHeader {
    family: String,
    canonical_name: String,
}

fn parse_table_header(trimmed_line: &str) -> Option<ParsedTableHeader> {
    let after_table = trimmed_line.strip_prefix("table ")?;
    let mut parts = after_table.splitn(2, ' ');
    let family = parts.next()?.to_owned();
    let rest = parts.next()?;
    // Name is up to the first space or `{`.
    let name_end = rest.find([' ', '{']).unwrap_or(rest.len());
    let canonical_name = rest[..name_end].trim().to_owned();
    if family.is_empty() || canonical_name.is_empty() {
        return None;
    }
    Some(ParsedTableHeader {
        family,
        canonical_name,
    })
}

// ── D13.b — service-port tunnel scoping (nas / llm) ───────────────────

/// Reviewed table-name prefix for service-hosting port scoping
/// (`inet rustynet_svc_nas`, `inet rustynet_svc_llm`).
pub const REVIEWED_SERVICE_TABLE_PREFIX: &str = "rustynet_svc_";

/// Fail-closed input validation error for the service-scope
/// renderer. The renderer feeds `nft -f` via the privileged helper,
/// so every field is strictly validated — no untrusted value reaches
/// rule text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceScopeRenderError {
    pub reason: String,
}

impl std::fmt::Display for ServiceScopeRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "service scope render refused: {}", self.reason)
    }
}

impl std::error::Error for ServiceScopeRenderError {}

fn validate_service_label(service: &str) -> Result<(), ServiceScopeRenderError> {
    if service.is_empty() || service.len() > 16 || !service.bytes().all(|b| b.is_ascii_lowercase())
    {
        return Err(ServiceScopeRenderError {
            reason: format!("service label {service:?} must be 1-16 ascii lowercase letters"),
        });
    }
    Ok(())
}

fn validate_interface_name(iface: &str) -> Result<(), ServiceScopeRenderError> {
    // Agrees with the privileged helper's `is_interface_name` and the
    // daemon's `validate_net_device_name`: neither admits `.` (no dots,
    // `..`-style tricks or trailing-dot ambiguity), so neither does this
    // renderer-side validation.
    if iface.is_empty()
        || iface.len() > 15
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ServiceScopeRenderError {
            reason: format!("interface name {iface:?} must be 1-15 chars of [A-Za-z0-9_-]"),
        });
    }
    Ok(())
}

/// Render the belt-and-braces nftables table that scopes a
/// service-hosting port to the tunnel interface: any packet to the
/// service port that did not arrive on the tunnel interface is
/// dropped, regardless of the listener's bind address. This sits on
/// top of (never instead of) the tunnel-only bind validation in
/// `crate::service_exposure::validate_tunnel_only_bind` —
/// SecurityMinimumBar §6.E control E1's second layer.
///
/// All inputs are strictly validated; the output is deterministic
/// canonical text suitable for `nft -f` and for snapshot comparison.
pub fn render_service_port_tunnel_scope_table(
    service: &str,
    port: u16,
    tunnel_iface: &str,
) -> Result<String, ServiceScopeRenderError> {
    validate_service_label(service)?;
    validate_interface_name(tunnel_iface)?;
    if port == 0 {
        return Err(ServiceScopeRenderError {
            reason: "service port must be non-zero".to_owned(),
        });
    }
    Ok(format!(
        "table inet {REVIEWED_SERVICE_TABLE_PREFIX}{service} {{\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority -10; policy accept;\n\
         \t\ttcp dport {port} iifname != \"{tunnel_iface}\" drop\n\
         \t}}\n\
         }}\n",
    ))
}

// ── CS3 — gossip port tunnel scoping (udp/51821) ──────────────────────

/// The single reviewed table that scopes the gossip UDP port to the tunnel.
/// A FIXED name (not generation-numbered, not `rustynet_g…`) on purpose: it
/// is not part of the killswitch table's reviewed chain set (so
/// `evaluate_linux_runtime_nftables_snapshot` and the boot verifier are
/// unaffected — the collector files it under "non-reviewed rustynet tables",
/// forensic only) and `prune_owned_tables` (which sweeps `rustynet_g…`)
/// never touches it. The privileged helper admits exactly this name, not the
/// `rustynet_svc_` prefix.
pub const GOSSIP_SCOPE_TABLE: &str = "rustynet_svc_gossip";
/// The one base chain in [`GOSSIP_SCOPE_TABLE`].
pub const GOSSIP_SCOPE_CHAIN: &str = "input";
/// `input` hook priority of the scope chain: before the default-priority
/// (0) filter chains so the drop lands first. The chain's policy is ACCEPT:
/// it never admits anything on its own, it only drops.
pub const GOSSIP_SCOPE_HOOK_PRIORITY: &str = "-10";

/// Rule tokens (one word per argv element, the shape the privileged helper
/// allowlist matches) that accept gossip-port datagrams from LOCAL senders
/// only. `iifname lo` can only be set by the kernel for locally originated
/// traffic, so this admits nothing from the network. It exists so a local
/// process (the chaos flood stage, diagnostics) can still reach the socket;
/// it must precede the drop.
pub fn gossip_scope_loopback_accept_tokens(port: u16) -> Vec<String> {
    vec![
        "udp".into(),
        "dport".into(),
        port.to_string(),
        "iifname".into(),
        "lo".into(),
        "accept".into(),
    ]
}

/// Rule tokens that drop gossip-port datagrams arriving on ANY interface
/// other than the tunnel. This is the interface-level pin that binding to the
/// overlay address alone cannot give (Linux accepts a packet for a local
/// address on any interface).
pub fn gossip_scope_tunnel_drop_tokens(
    port: u16,
    tunnel_iface: &str,
) -> Result<Vec<String>, ServiceScopeRenderError> {
    validate_interface_name(tunnel_iface)?;
    if tunnel_iface == "lo" {
        return Err(ServiceScopeRenderError {
            reason: "the tunnel interface cannot be `lo`; that would scope the port to loopback"
                .to_owned(),
        });
    }
    if port == 0 {
        return Err(ServiceScopeRenderError {
            reason: "gossip port must be non-zero".to_owned(),
        });
    }
    Ok(vec![
        "udp".into(),
        "dport".into(),
        port.to_string(),
        "iifname".into(),
        "!=".into(),
        tunnel_iface.to_owned(),
        "drop".into(),
    ])
}

/// argv (one `nft` invocation each, in order) that create the table, its
/// base chain and the two rules from scratch. Rule order matters (nft is
/// first-match): the loopback accept precedes the drop.
pub fn gossip_scope_install_argvs(
    port: u16,
    tunnel_iface: &str,
) -> Result<Vec<Vec<String>>, ServiceScopeRenderError> {
    let drop_tokens = gossip_scope_tunnel_drop_tokens(port, tunnel_iface)?;
    let rule = |tokens: Vec<String>| -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            GOSSIP_SCOPE_TABLE.into(),
            GOSSIP_SCOPE_CHAIN.into(),
        ];
        argv.extend(tokens);
        argv
    };
    Ok(vec![
        vec![
            "add".into(),
            "table".into(),
            "inet".into(),
            GOSSIP_SCOPE_TABLE.into(),
        ],
        vec![
            "add".into(),
            "chain".into(),
            "inet".into(),
            GOSSIP_SCOPE_TABLE.into(),
            GOSSIP_SCOPE_CHAIN.into(),
            "{".into(),
            "type".into(),
            "filter".into(),
            "hook".into(),
            "input".into(),
            "priority".into(),
            GOSSIP_SCOPE_HOOK_PRIORITY.into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
        rule(gossip_scope_loopback_accept_tokens(port)),
        rule(drop_tokens),
    ])
}

/// The argv that removes the scope table (idempotent at the call site via
/// allow-failure; deleting the table removes the chain and both rules).
pub fn gossip_scope_teardown_argv() -> Vec<String> {
    vec![
        "delete".into(),
        "table".into(),
        "inet".into(),
        GOSSIP_SCOPE_TABLE.into(),
    ]
}

/// Canonical `nft -f` text for the scope table (deterministic; the reviewed
/// golden and the human-readable statement of what the argv above builds).
pub fn render_gossip_scope_table(
    port: u16,
    tunnel_iface: &str,
) -> Result<String, ServiceScopeRenderError> {
    let drop_tokens = gossip_scope_tunnel_drop_tokens(port, tunnel_iface)?;
    // Same tokens as the argv, with the interface name quoted the way nft
    // prints it back, so the text and the argv cannot drift apart.
    let drop_rule = drop_tokens
        .iter()
        .map(|token| {
            if token == tunnel_iface {
                format!("\"{token}\"")
            } else {
                token.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let accept_rule = gossip_scope_loopback_accept_tokens(port)
        .iter()
        .map(|token| {
            if token == "lo" {
                "\"lo\"".to_owned()
            } else {
                token.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        "table inet {GOSSIP_SCOPE_TABLE} {{\n\
         \tchain {GOSSIP_SCOPE_CHAIN} {{\n\
         \t\ttype filter hook input priority {GOSSIP_SCOPE_HOOK_PRIORITY}; policy accept;\n\
         \t\t{accept_rule}\n\
         \t\t{drop_rule}\n\
         \t}}\n\
         }}\n",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with(
        inet_chains: Option<Vec<&str>>,
        ip_nat_chains: Option<Vec<&str>>,
        ip6_nat_chains: Option<Vec<&str>>,
    ) -> LinuxRuntimeNftablesSnapshot {
        let mut reviewed_tables = Vec::new();
        if let Some(chains) = inet_chains {
            reviewed_tables.push(ObservedNftablesTable {
                family: "inet".to_owned(),
                canonical_name: REVIEWED_INET_TABLE.to_owned(),
                chains: chains.iter().map(|c| (*c).to_owned()).collect(),
            });
        }
        if let Some(chains) = ip_nat_chains {
            reviewed_tables.push(ObservedNftablesTable {
                family: "ip".to_owned(),
                canonical_name: REVIEWED_IP_NAT_TABLE.to_owned(),
                chains: chains.iter().map(|c| (*c).to_owned()).collect(),
            });
        }
        if let Some(chains) = ip6_nat_chains {
            reviewed_tables.push(ObservedNftablesTable {
                family: "ip6".to_owned(),
                canonical_name: REVIEWED_IP6_NAT_TABLE.to_owned(),
                chains: chains.iter().map(|c| (*c).to_owned()).collect(),
            });
        }
        LinuxRuntimeNftablesSnapshot {
            ruleset_source: "test".to_owned(),
            host_observable: true,
            reviewed_tables,
            non_reviewed_rustynet_tables: Vec::new(),
        }
    }

    #[test]
    fn evaluator_passes_clean_inet_plus_ip_nat_snapshot() {
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            None,
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(
            reasons.is_empty(),
            "clean snapshot must produce no drift; got: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_inet_table() {
        let snapshot = snapshot_with(None, Some(vec!["postrouting"]), None);
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(reasons.iter().any(|r| r.contains("inet rustynet")));
    }

    #[test]
    fn evaluator_rejects_missing_ip_nat_table() {
        let snapshot = snapshot_with(Some(vec!["killswitch", "forward"]), None, None);
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(reasons.iter().any(|r| r.contains("ip rustynet_nat")));
    }

    #[test]
    fn evaluator_rejects_missing_required_chain() {
        // inet table present, but `forward` chain missing.
        let snapshot = snapshot_with(Some(vec!["killswitch"]), Some(vec!["postrouting"]), None);
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(
            reasons.iter().any(|r| r.contains("`forward` missing")),
            "missing forward chain must trip drift; got: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unexpected_chain() {
        // An extra `bypass` chain that isn't in the reviewed set is
        // a security-grade reject — a hostile operator script could
        // insert a parallel chain that widens the policy.
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward", "bypass"]),
            Some(vec!["postrouting"]),
            None,
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("unexpected chain `bypass`")),
            "extra chain must trip drift; got: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_missing_ip6_nat_when_parity_not_required() {
        // When `ipv6_parity_required=false`, the absence of `ip6
        // rustynet_nat` is informational and must NOT contribute to
        // the verdict. This is the pre-L7-flip steady state.
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            None,
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy {
                ipv6_parity_required: false,
            },
        );
        assert!(reasons.is_empty(), "ipv6-not-required snapshot must pass");
    }

    #[test]
    fn evaluator_rejects_missing_ip6_nat_when_parity_required() {
        // Post-L7 flip: `ipv6_parity_required=true` makes the absence
        // of the `ip6 rustynet_nat` sibling table a hard reject.
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            None,
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy {
                ipv6_parity_required: true,
            },
        );
        assert!(
            reasons.iter().any(|r| r.contains("ip6 rustynet_nat")),
            "ipv6-required + missing ip6 must trip drift; got: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_clean_ip6_nat_sibling_when_required() {
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            Some(vec!["postrouting"]),
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy {
                ipv6_parity_required: true,
            },
        );
        assert!(
            reasons.is_empty(),
            "clean ipv6-parity snapshot must pass; got: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_off_linux_host() {
        // The collector sets `host_observable=false` off-Linux. The
        // evaluator must surface a clear blocker before any chain
        // checks fire, otherwise an empty Vec<Reviewed_Table> from
        // the stub collector would produce misleading "missing X"
        // reasons.
        let snapshot = LinuxRuntimeNftablesSnapshot {
            ruleset_source: "off-linux stub".to_owned(),
            host_observable: false,
            reviewed_tables: Vec::new(),
            non_reviewed_rustynet_tables: Vec::new(),
        };
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert_eq!(
            reasons.len(),
            1,
            "off-linux must short-circuit to one reason"
        );
        assert!(reasons[0].contains("Linux runtime host"));
    }

    #[test]
    fn build_report_marks_overall_ok_only_when_no_drift() {
        let clean = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            None,
        );
        let report =
            build_linux_runtime_nftables_report(clean, LinuxRuntimeNftablesPolicy::default());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());

        let dirty = snapshot_with(Some(vec!["killswitch"]), None, None);
        let report =
            build_linux_runtime_nftables_report(dirty, LinuxRuntimeNftablesPolicy::default());
        assert!(!report.overall_ok);
        assert!(!report.drift_reasons.is_empty());
    }

    #[test]
    fn strip_generation_suffix_handles_canonical_and_rotated_forms() {
        assert_eq!(strip_generation_suffix("rustynet"), "rustynet");
        assert_eq!(strip_generation_suffix("rustynet_g1"), "rustynet");
        assert_eq!(strip_generation_suffix("rustynet_g99"), "rustynet");
        assert_eq!(strip_generation_suffix("rustynet_nat_g1"), "rustynet_nat");
        // No suffix → unchanged.
        assert_eq!(strip_generation_suffix("rustynet_other"), "rustynet_other");
        // Non-digit after `_g` → not a generation marker.
        assert_eq!(
            strip_generation_suffix("rustynet_geometry"),
            "rustynet_geometry"
        );
    }

    #[test]
    fn parse_nft_ruleset_recognises_inet_and_ip_nat_families() {
        let body = "\
table inet rustynet_g1 {
  chain killswitch {
    type filter hook output priority 0; policy drop;
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
table ip rustynet_nat_g1 {
  chain postrouting {
    type nat hook postrouting priority 100;
  }
}
";
        let snapshot = parse_nft_ruleset(body);
        assert_eq!(snapshot.reviewed_tables.len(), 2);
        let inet = snapshot
            .reviewed_tables
            .iter()
            .find(|t| t.family == "inet")
            .expect("inet table present");
        assert_eq!(inet.canonical_name, REVIEWED_INET_TABLE);
        assert_eq!(
            inet.chains,
            vec!["killswitch".to_owned(), "forward".to_owned()]
        );
        let nat = snapshot
            .reviewed_tables
            .iter()
            .find(|t| t.family == "ip")
            .expect("ip nat table present");
        assert_eq!(nat.canonical_name, REVIEWED_IP_NAT_TABLE);
        assert_eq!(nat.chains, vec!["postrouting".to_owned()]);
    }

    #[test]
    fn parse_nft_ruleset_records_non_reviewed_rustynet_tables_for_forensics() {
        // A hostile-or-broken operator script might insert
        // `table inet rustynet_extra` as a parallel widening
        // surface. The parser MUST surface it (so the operator
        // sees it) without conflating it with the reviewed set.
        let body = "\
table inet rustynet_extra {
  chain whatever { type filter hook output priority 0; }
}
";
        let snapshot = parse_nft_ruleset(body);
        assert!(snapshot.reviewed_tables.is_empty());
        assert!(
            snapshot
                .non_reviewed_rustynet_tables
                .iter()
                .any(|t| t.contains("rustynet_extra")),
            "non-reviewed rustynet_extra must surface in forensics; got: {:?}",
            snapshot.non_reviewed_rustynet_tables
        );
    }

    #[test]
    fn parse_nft_ruleset_round_trip_through_evaluator_passes_clean_runtime() {
        let body = "\
table inet rustynet_g2 {
  chain killswitch {
    type filter hook output priority 0; policy drop;
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
table ip rustynet_nat_g2 {
  chain postrouting {
    type nat hook postrouting priority 100;
  }
}
";
        let snapshot = parse_nft_ruleset(body);
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(
            reasons.is_empty(),
            "parser→evaluator round trip on clean ruleset must pass; got: {reasons:?}"
        );
    }

    #[test]
    fn schema_version_pin_guards_against_silent_bump() {
        let snapshot = snapshot_with(
            Some(vec!["killswitch", "forward"]),
            Some(vec!["postrouting"]),
            None,
        );
        let report =
            build_linux_runtime_nftables_report(snapshot, LinuxRuntimeNftablesPolicy::default());
        assert_eq!(report.schema_version, 1);
    }

    // ── CS3: gossip port scope ───────────────────────────────────────

    #[test]
    fn gossip_scope_table_golden_text() {
        let text = render_gossip_scope_table(51821, "rustynet0").expect("render");
        assert_eq!(
            text,
            "table inet rustynet_svc_gossip {\n\
             \tchain input {\n\
             \t\ttype filter hook input priority -10; policy accept;\n\
             \t\tudp dport 51821 iifname \"lo\" accept\n\
             \t\tudp dport 51821 iifname != \"rustynet0\" drop\n\
             \t}\n\
             }\n"
        );
        // Accept-policy chain, exactly one drop, nothing that could admit
        // traffic the rest of the ruleset did not already admit.
        assert_eq!(text.matches("drop").count(), 1);
        assert_eq!(text.matches("accept").count(), 2); // policy + loopback
        assert!(!text.contains("policy drop"));
    }

    #[test]
    fn gossip_scope_install_argvs_match_the_rendered_table() {
        let argvs = gossip_scope_install_argvs(51821, "rustynet0").expect("argvs");
        assert_eq!(argvs.len(), 4);
        assert_eq!(argvs[0], ["add", "table", "inet", "rustynet_svc_gossip"]);
        assert_eq!(
            argvs[1],
            [
                "add",
                "chain",
                "inet",
                "rustynet_svc_gossip",
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "-10",
                ";",
                "policy",
                "accept",
                ";",
                "}"
            ]
        );
        assert_eq!(
            argvs[2],
            [
                "add",
                "rule",
                "inet",
                "rustynet_svc_gossip",
                "input",
                "udp",
                "dport",
                "51821",
                "iifname",
                "lo",
                "accept"
            ]
        );
        assert_eq!(
            argvs[3],
            [
                "add",
                "rule",
                "inet",
                "rustynet_svc_gossip",
                "input",
                "udp",
                "dport",
                "51821",
                "iifname",
                "!=",
                "rustynet0",
                "drop"
            ]
        );
        // Loopback accept strictly precedes the drop (first-match).
        let accept_at = argvs
            .iter()
            .position(|a| a.last().map(String::as_str) == Some("accept"));
        let drop_at = argvs
            .iter()
            .position(|a| a.last().map(String::as_str) == Some("drop"));
        assert!(accept_at < drop_at);
        assert_eq!(
            gossip_scope_teardown_argv(),
            ["delete", "table", "inet", "rustynet_svc_gossip"]
        );
    }

    #[test]
    fn gossip_scope_rejects_unsafe_inputs() {
        for bad in [
            "",
            "lo",
            "a b",
            "x;y",
            "rustynet0\n",
            "waytoolonginterfacename",
            "a\"b",
            // CS3 fix (nit): `.` is NOT admitted — the renderer's interface
            // validation must agree with the helper's `is_interface_name` and
            // the daemon's `validate_net_device_name`, neither of which
            // allows dots.
            "rustynet.0",
        ] {
            assert!(
                gossip_scope_tunnel_drop_tokens(51821, bad).is_err(),
                "{bad:?} must be refused"
            );
            assert!(gossip_scope_install_argvs(51821, bad).is_err());
            assert!(render_gossip_scope_table(51821, bad).is_err());
        }
        assert!(gossip_scope_tunnel_drop_tokens(0, "rustynet0").is_err());
    }

    #[test]
    fn gossip_scope_table_is_filed_as_non_reviewed_by_the_collector() {
        // Not a reviewed killswitch/NAT table: it must neither be demanded
        // by nor trip the runtime evaluator (extra-chain drift applies to
        // the reviewed tables only).
        let body = format!(
            "table inet rustynet_g1 {{\n  chain killswitch {{\n  }}\n  chain forward {{\n  }}\n}}\n\
             table ip rustynet_nat_g1 {{\n  chain postrouting {{\n  }}\n}}\n{}",
            render_gossip_scope_table(51821, "rustynet0").expect("render")
        );
        let snapshot = parse_nft_ruleset(&body);
        assert!(
            snapshot
                .non_reviewed_rustynet_tables
                .iter()
                .any(|name| name.contains("rustynet_svc_gossip")),
            "got {:?}",
            snapshot.non_reviewed_rustynet_tables
        );
        let reasons = evaluate_linux_runtime_nftables_snapshot(
            &snapshot,
            LinuxRuntimeNftablesPolicy::default(),
        );
        assert!(
            reasons.is_empty(),
            "the scope table must not create drift: {reasons:?}"
        );
    }
}
