//! Conntrack invalidation for a NAT generation change (QH-47).
//!
//! # Why this module exists
//!
//! netfilter traverses a `nat` chain only for the FIRST packet of a flow. Once
//! conntrack confirms the flow, its NAT binding — or the absence of one — is
//! fixed in the conntrack entry, and every later packet of that flow is
//! translated from the entry without ever re-entering the nat hook.
//!
//! The dataplane rebuilds its nat table per generation (`rustynet_nat_g<N>`)
//! and deletes the previous one, but a flow that was already established when
//! the new masquerade appeared keeps its old, un-NATed binding. Because a
//! conntrack entry is refreshed by every packet that matches it, a steady
//! traffic stream keeps that stale binding alive indefinitely rather than
//! ageing it out: traffic that should be NATed after the role change never is.
//!
//! The inverse direction is the security-relevant one. When a node stops
//! serving an exit and the masquerade is removed, flows that already hold a NAT
//! binding keep being translated and keep egressing to the internet through a
//! host that has withdrawn the capability. That is exactly the §10.7 residue
//! class — a control's effects outliving the role that justified it.
//!
//! # The selector, and what a broader one would break
//!
//! The only flows a masquerade generation change invalidates are the ones whose
//! ORIGINAL SOURCE is a mesh address: those are the flows the mesh masquerade
//! would rewrite (or has stopped rewriting). So the grammar expresses exactly
//! one delete filter — `conntrack -D --family ipv4 --orig-src <mesh_cidr>` —
//! and nothing else.
//!
//! * **`conntrack -F` (flush the whole table) is unrepresentable.** A blanket
//!   flush destroys every unrelated long-lived flow on the host: the operator's
//!   own SSH session into the node, the daemon's control-plane connection to
//!   the coordinator, the WireGuard UDP association itself, and every service
//!   the box happens to run. On a node that is also somebody's workstation that
//!   is a full outage caused by a role change that should have been invisible
//!   to all of it.
//! * **An interface selector does not exist.** Conntrack tuples carry no
//!   interface, so `-D` cannot be filtered by egress device; the source network
//!   is the closest available proxy and is in fact the more precise one, since
//!   it names the traffic class rather than the path.
//! * **Selecting on NAT state is backwards.** `--status`/`--nat-src` would
//!   match entries that are ALREADY translated, which is the complement of the
//!   set the install direction needs to clear.
//! * **The source network cannot be widened into a blanket flush**, because it
//!   is validated with the same bounded private/CGNAT/ULA containment check the
//!   pf egress source uses ([`crate::macos_pf_mesh_cidr`]). `0.0.0.0/0` — the
//!   value that would turn this selective delete into `-F` by another name — is
//!   refused on both sides of the privileged boundary, and the address must be
//!   the canonical network address of its prefix so no host-bit trickery can
//!   smuggle a different range past a reader.
//!
//! The blast radius is therefore bounded to mesh-sourced flows, all of which
//! traverse the tunnel this daemon owns and all of which the client re-opens.
//!
//! # Family
//!
//! IPv4 only, and IPv6 is unrepresentable rather than merely rejected: the
//! family is a single-variant enum. The masquerade this flush accompanies is
//! installed into an `ip` (v4) nft table, and IPv6 egress is hard-disabled
//! unless the generation declares v6 parity. When a v6 exit NAT lands, adding
//! the variant is a deliberate, reviewable edit rather than an accident of a
//! permissive validator.
//!
//! This module is pure: it decodes/encodes the helper's argv grammar and parses
//! the outcome line the builtin emits. Privileged execution lives in
//! `privileged_helper`.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

/// Helper program name for the in-helper conntrack flush builtin.
pub const LINUX_CONNTRACK_FLUSH_PROGRAM: &str = "linux-conntrack-flush";

/// The address family of the flush.
///
/// Deliberately single-variant. See the module docs: an IPv6 flush is not a
/// value this grammar can carry, so it cannot be requested by a daemon
/// compromised to the helper's uid either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackFlushFamily {
    Ipv4,
}

impl ConntrackFlushFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ConntrackFlushFamily::Ipv4 => "ipv4",
        }
    }

    /// Exact-match parse with no default arm.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ipv4" => Some(ConntrackFlushFamily::Ipv4),
            _ => None,
        }
    }
}

/// A decoded request for the builtin: delete conntrack entries whose ORIGINAL
/// source lies inside `orig_src`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackFlushSpec {
    pub family: ConntrackFlushFamily,
    pub orig_src: String,
}

impl ConntrackFlushSpec {
    /// Build a spec for the mesh source network, validating it up front so the
    /// daemon never even constructs an argv it would be refused for.
    pub fn for_mesh_source(mesh_cidr: &str) -> Result<Self, String> {
        let spec = Self {
            family: ConntrackFlushFamily::Ipv4,
            orig_src: mesh_cidr.to_owned(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Render the argv the daemon sends. Exactly two tokens. There is no token
    /// for a table, a protocol, a destination, an operation, or a "flush all"
    /// switch, because no such token exists in the grammar.
    pub fn encode(&self) -> Vec<String> {
        vec![
            format!("family={}", self.family.as_str()),
            format!("orig-src={}", self.orig_src),
        ]
    }

    /// Decode and validate the helper-side argv.
    ///
    /// Decode success IS the validation, matching the macOS pf-load and
    /// firewalld-zone builtins: the helper's `validate_request` arm calls this
    /// and nothing else, so any shape this refuses is a shape the helper will
    /// not execute.
    pub fn decode(args: &[&str]) -> Result<Self, String> {
        let mut family: Option<&str> = None;
        let mut orig_src: Option<&str> = None;
        for arg in args {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| format!("conntrack flush token is not key=value: {arg:?}"))?;
            match key {
                "family" => set_once(&mut family, key, value)?,
                "orig-src" => set_once(&mut orig_src, key, value)?,
                _ => return Err(format!("unknown conntrack flush token: {key:?}")),
            }
        }
        let family =
            family.ok_or_else(|| "conntrack flush spec missing token: family".to_owned())?;
        let orig_src =
            orig_src.ok_or_else(|| "conntrack flush spec missing token: orig-src".to_owned())?;
        let family = ConntrackFlushFamily::parse(family)
            .ok_or_else(|| format!("unsupported conntrack flush family: {family:?}"))?;
        let spec = Self {
            family,
            orig_src: orig_src.to_owned(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// The argv the helper hands to `conntrack`. Every token is a helper-owned
    /// literal except the source network, which `validate` has already
    /// constrained to a canonical, bounded, private/CGNAT IPv4 network.
    pub fn conntrack_argv(&self) -> Vec<String> {
        vec![
            "-D".to_owned(),
            "--family".to_owned(),
            self.family.as_str().to_owned(),
            "--orig-src".to_owned(),
            self.orig_src.clone(),
        ]
    }

    /// Source-network validation applied on BOTH sides of the boundary.
    fn validate(&self) -> Result<(), String> {
        // Bounded private/CGNAT/ULA containment: this is the check that makes a
        // blanket flush unrepresentable, and it is the SAME validator the pf
        // egress source uses, so the two boundaries cannot drift apart.
        crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr(self.orig_src.as_str())?;
        let (network, prefix) = parse_ipv4_cidr(self.orig_src.as_str()).ok_or_else(|| {
            format!(
                "conntrack flush source must be an IPv4 CIDR to match family {}: {:?}",
                self.family.as_str(),
                self.orig_src
            )
        })?;
        if !is_canonical_ipv4_network(network, prefix) {
            return Err(format!(
                "conntrack flush source must be the canonical network address of its prefix: {:?}",
                self.orig_src
            ));
        }
        Ok(())
    }
}

/// Parse `a.b.c.d/len` as IPv4, or `None` for anything else (including a
/// syntactically valid IPv6 CIDR, which the single-variant family forbids).
fn parse_ipv4_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr_raw, prefix_raw) = value.split_once('/')?;
    let addr: Ipv4Addr = addr_raw.parse().ok()?;
    let prefix: u8 = prefix_raw.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((addr, prefix))
}

/// True when no host bits are set, i.e. the text names the network it appears
/// to name. `100.64.0.0/10` passes; `100.64.0.5/10` does not.
fn is_canonical_ipv4_network(addr: Ipv4Addr, prefix: u8) -> bool {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(addr) & !mask == 0
}

/// What the builtin did, parsed from its structured stdout line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackFlushOutcome {
    /// The flush ran. `entries` is the count `conntrack` reported deleted; zero
    /// is a normal, successful result (nothing matched the selector).
    Flushed { entries: u64 },
    /// `conntrack` (conntrack-tools) is not installed on this host, so the
    /// stale bindings could not be invalidated.
    ///
    /// This is a REPORTED outcome, never a silently-swallowed one, and never
    /// mapped onto `Flushed { entries: 0 }` — "nothing matched" and "the flush
    /// never happened" are different facts and callers must be able to tell
    /// them apart.
    ToolAbsent,
    /// This platform's exit NAT is not nftables/conntrack based (macOS `pf`,
    /// Windows). Not an error and not a degradation of this control; the
    /// equivalent state flush for those platforms is separate work.
    PlatformUnsupported,
}

impl ConntrackFlushOutcome {
    /// Render the single structured line the builtin writes to stdout.
    pub fn encode(&self) -> String {
        match self {
            ConntrackFlushOutcome::Flushed { entries } => {
                format!("outcome=flushed entries={entries}")
            }
            ConntrackFlushOutcome::ToolAbsent => "outcome=tool-absent".to_owned(),
            ConntrackFlushOutcome::PlatformUnsupported => "outcome=platform-unsupported".to_owned(),
        }
    }

    /// Parse the builtin's stdout.
    ///
    /// Fails closed on anything it does not understand. An unparseable outcome
    /// must surface as an error rather than default-construct into something
    /// that reads like a successful flush — a fabricated success here would
    /// hide precisely the condition QH-47 exists to make visible.
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut outcome: Option<&str> = None;
        let mut entries: Option<u64> = None;
        for token in line.split_whitespace() {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                format!("conntrack flush outcome token is not key=value: {token:?}")
            })?;
            match key {
                "outcome" => set_once(&mut outcome, key, value)?,
                "entries" => {
                    if entries.is_some() {
                        return Err("duplicate conntrack flush outcome token: entries".to_owned());
                    }
                    entries = Some(value.parse::<u64>().map_err(|_| {
                        format!("conntrack flush entry count is not a number: {value:?}")
                    })?);
                }
                other => {
                    return Err(format!("unknown conntrack flush outcome token: {other:?}"));
                }
            }
        }
        let outcome =
            outcome.ok_or_else(|| "conntrack flush outcome missing token: outcome".to_owned())?;
        match outcome {
            "flushed" => {
                let entries = entries.ok_or_else(|| {
                    "conntrack flush outcome 'flushed' requires an entries count".to_owned()
                })?;
                Ok(ConntrackFlushOutcome::Flushed { entries })
            }
            "tool-absent" if entries.is_none() => Ok(ConntrackFlushOutcome::ToolAbsent),
            "platform-unsupported" if entries.is_none() => {
                Ok(ConntrackFlushOutcome::PlatformUnsupported)
            }
            other => Err(format!("unknown conntrack flush outcome: {other:?}")),
        }
    }
}

/// Extract the deleted-entry count from `conntrack -D`'s summary line.
///
/// `conntrack` prints `conntrack v1.4.7 (conntrack-tools): N flow entries have
/// been deleted.` on stderr, and exits NON-ZERO when `N == 0`. That exit status
/// is not a failure — it is "the selector matched nothing", the normal result
/// on a node with no established mesh flows — so the count, not the status, is
/// the success signal. Returns `None` when no summary line is present, which
/// callers treat as a real failure.
pub fn parse_deleted_entry_count(stream: &str) -> Option<u64> {
    const MARKER: &str = "flow entries have been deleted";
    for line in stream.lines() {
        let Some(head) = line.split(MARKER).next() else {
            continue;
        };
        if !line.contains(MARKER) {
            continue;
        }
        if let Some(count) = head.split_whitespace().next_back()
            && let Ok(parsed) = count.parse::<u64>()
        {
            return Some(parsed);
        }
    }
    None
}

fn set_once<'a>(slot: &mut Option<&'a str>, key: &str, value: &'a str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate conntrack flush token: {key}"));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips_over_the_two_token_grammar() {
        let spec = ConntrackFlushSpec::for_mesh_source("100.64.0.0/10").unwrap();
        let argv = spec.encode();
        assert_eq!(argv, vec!["family=ipv4", "orig-src=100.64.0.0/10"]);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_eq!(ConntrackFlushSpec::decode(&borrowed).unwrap(), spec);
    }

    /// The conntrack argv is fully determined by the spec, carries the delete
    /// filter and nothing else, and never contains a blanket-flush switch.
    #[test]
    fn conntrack_argv_is_a_selective_delete_only() {
        let spec = ConntrackFlushSpec::for_mesh_source("100.64.0.0/10").unwrap();
        assert_eq!(
            spec.conntrack_argv(),
            vec!["-D", "--family", "ipv4", "--orig-src", "100.64.0.0/10"]
        );
        for forbidden in ["-F", "--flush", "-L", "-E", "-U", "--nat-src", "-p"] {
            assert!(
                !spec.conntrack_argv().iter().any(|token| token == forbidden),
                "argv must not carry {forbidden}"
            );
        }
    }

    /// The security property that makes this grammar safe: a caller cannot ask
    /// for a table flush, cannot add a second filter, and cannot smuggle a free
    /// string, because no such token exists.
    #[test]
    fn unknown_tokens_are_refused_rather_than_ignored() {
        for argv in [
            vec!["family=ipv4", "orig-src=100.64.0.0/10", "op=flush"],
            vec!["family=ipv4", "orig-src=100.64.0.0/10", "-F"],
            vec!["family=ipv4", "orig-src=100.64.0.0/10", "--flush"],
            vec!["family=ipv4", "orig-src=100.64.0.0/10", "proto=tcp"],
            vec![
                "family=ipv4",
                "orig-src=100.64.0.0/10",
                "orig-dst=8.8.8.8/32",
            ],
            vec!["family=ipv4", "orig-src=100.64.0.0/10", "zone=1"],
        ] {
            assert!(
                ConntrackFlushSpec::decode(&argv).is_err(),
                "must refuse: {argv:?}"
            );
        }
    }

    /// QH-45 near-miss pattern: argv ONE token off the allowed shape is
    /// refused. Every case below is a single mutation of a vector that is
    /// otherwise exactly right.
    #[test]
    fn near_miss_argv_shapes_are_refused() {
        let good = vec!["family=ipv4", "orig-src=100.64.0.0/10"];
        assert!(
            ConntrackFlushSpec::decode(&good).is_ok(),
            "baseline must pass"
        );

        for argv in [
            // key misspelled by one character
            vec!["famly=ipv4", "orig-src=100.64.0.0/10"],
            vec!["family=ipv4", "orig-srcs=100.64.0.0/10"],
            vec!["family=ipv4", "orig_src=100.64.0.0/10"],
            // the conntrack long-option spelling instead of the grammar's key
            vec!["family=ipv4", "--orig-src=100.64.0.0/10"],
            // value case / whitespace one character off
            vec!["family=IPv4", "orig-src=100.64.0.0/10"],
            vec!["family=ipv4 ", "orig-src=100.64.0.0/10"],
            vec!["family=ipv4", "orig-src=100.64.0.0/10 "],
            // separator dropped
            vec!["familyipv4", "orig-src=100.64.0.0/10"],
            // one token missing
            vec!["orig-src=100.64.0.0/10"],
            vec!["family=ipv4"],
            // one token duplicated
            vec!["family=ipv4", "family=ipv4", "orig-src=100.64.0.0/10"],
            vec![
                "family=ipv4",
                "orig-src=100.64.0.0/10",
                "orig-src=10.0.0.0/8",
            ],
            // empty values
            vec!["family=", "orig-src=100.64.0.0/10"],
            vec!["family=ipv4", "orig-src="],
            // prefix one bit wider than the CGNAT block it claims to be
            vec!["family=ipv4", "orig-src=100.64.0.0/9"],
            // host bits set: names a different range than it reads as
            vec!["family=ipv4", "orig-src=100.64.0.1/10"],
        ] {
            assert!(
                ConntrackFlushSpec::decode(&argv).is_err(),
                "near miss must be refused: {argv:?}"
            );
        }
    }

    /// The blanket flush must be UNREPRESENTABLE, not merely improbable: the
    /// one value that would turn this selective delete into `conntrack -F` by
    /// another name is refused on both sides of the boundary.
    #[test]
    fn blanket_and_global_source_ranges_are_refused() {
        for cidr in [
            "0.0.0.0/0",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "8.8.8.0/24",
            "100.0.0.0/8",
            "172.16.0.0/8",
        ] {
            assert!(
                ConntrackFlushSpec::for_mesh_source(cidr).is_err(),
                "must refuse blanket/global source {cidr}"
            );
            assert!(
                ConntrackFlushSpec::decode(&["family=ipv4", &format!("orig-src={cidr}")]).is_err(),
                "must refuse blanket/global source over the wire: {cidr}"
            );
        }
    }

    /// IPv6 is unrepresentable rather than validated-against: neither the
    /// family token nor a v6 source can be carried, even though the shared
    /// containment validator accepts ULA ranges for the pf boundary.
    #[test]
    fn ipv6_is_unrepresentable_in_this_grammar() {
        assert!(ConntrackFlushFamily::parse("ipv6").is_none());
        assert!(ConntrackFlushSpec::decode(&["family=ipv6", "orig-src=fd7a::/48"]).is_err());
        // A ULA source passes the shared containment check but is still refused
        // here, because the family it belongs to does not exist in this spec.
        crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr("fd7a::/48")
            .expect("the shared validator accepts ULA");
        assert!(ConntrackFlushSpec::for_mesh_source("fd7a::/48").is_err());
        assert!(ConntrackFlushSpec::decode(&["family=ipv4", "orig-src=fd7a::/48"]).is_err());
    }

    #[test]
    fn legitimate_mesh_ranges_are_accepted() {
        for cidr in [
            "100.64.0.0/10",
            "100.64.1.0/24",
            "10.0.0.0/8",
            "10.42.0.0/16",
            "172.16.0.0/12",
            "192.168.1.0/24",
        ] {
            ConntrackFlushSpec::for_mesh_source(cidr)
                .unwrap_or_else(|err| panic!("{cidr} should be accepted: {err}"));
        }
    }

    #[test]
    fn outcome_round_trips() {
        for outcome in [
            ConntrackFlushOutcome::Flushed { entries: 0 },
            ConntrackFlushOutcome::Flushed { entries: 17 },
            ConntrackFlushOutcome::ToolAbsent,
            ConntrackFlushOutcome::PlatformUnsupported,
        ] {
            assert_eq!(
                ConntrackFlushOutcome::parse(&outcome.encode()).unwrap(),
                outcome
            );
        }
    }

    /// An unreadable outcome must be an error, never a value that reads like a
    /// successful flush.
    #[test]
    fn unparseable_outcome_fails_closed() {
        for bad in [
            "",
            "garbage",
            "outcome=flushed",
            "outcome=maybe",
            "outcome=tool-absent entries=3",
            "outcome=flushed entries=many",
            "entries=3",
            "outcome=flushed outcome=tool-absent entries=1",
        ] {
            assert!(
                ConntrackFlushOutcome::parse(bad).is_err(),
                "must refuse outcome {bad:?}"
            );
        }
    }

    /// "Nothing matched" and "the flush never ran" must never collapse into
    /// each other.
    #[test]
    fn tool_absent_is_distinguishable_from_a_zero_entry_flush() {
        assert_ne!(
            ConntrackFlushOutcome::ToolAbsent,
            ConntrackFlushOutcome::Flushed { entries: 0 }
        );
        assert_ne!(
            ConntrackFlushOutcome::ToolAbsent.encode(),
            ConntrackFlushOutcome::Flushed { entries: 0 }.encode()
        );
    }

    #[test]
    fn deleted_entry_counts_are_parsed_from_the_conntrack_summary() {
        assert_eq!(
            parse_deleted_entry_count(
                "conntrack v1.4.7 (conntrack-tools): 4 flow entries have been deleted."
            ),
            Some(4)
        );
        assert_eq!(
            parse_deleted_entry_count(
                "conntrack v1.4.5 (conntrack-tools): 0 flow entries have been deleted."
            ),
            Some(0)
        );
        assert_eq!(
            parse_deleted_entry_count(
                "tcp 6 431999 ESTABLISHED\n1 flow entries have been deleted."
            ),
            Some(1)
        );
        for bad in ["", "conntrack: command not found", "some flow entries"] {
            assert_eq!(
                parse_deleted_entry_count(bad),
                None,
                "must not parse {bad:?}"
            );
        }
    }

    #[test]
    fn canonical_network_check_is_exact() {
        assert!(is_canonical_ipv4_network(Ipv4Addr::new(100, 64, 0, 0), 10));
        assert!(is_canonical_ipv4_network(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(is_canonical_ipv4_network(Ipv4Addr::new(10, 1, 2, 3), 32));
        assert!(!is_canonical_ipv4_network(Ipv4Addr::new(100, 64, 0, 1), 10));
        assert!(!is_canonical_ipv4_network(Ipv4Addr::new(10, 1, 0, 0), 8));
    }
}
