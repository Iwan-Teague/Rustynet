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
}
