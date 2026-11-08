//! Origin DNS floor for protected Linux nodes — ki-0001 "floor-first", step 1.
//!
//! This module is the PURE CORE only (slice 1 of the adopted floor-first
//! fix, owner decision 2026-11-05): it owns the fixed table identity, the
//! exact nft batch text that installs/replaces or removes the floor, and a
//! strict fail-closed verifier for the effective listing. It performs no
//! process spawn, no file IO and no nft call, compiles on every OS the
//! sibling `linux_*` modules compile on, and has NO wiring: install-before-
//! backend-start, assertion points, rollback/`force_fail_closed` survival,
//! privileged-helper admission and the boot path are slice 2 (see
//! `FLOOR_SCOPE_NOTE` below for exactly what step 1 does not cover).
//!
//! # Why this exists
//!
//! The lab stage `exit_dns_failclosed_validation` fails on lenovo in about
//! half of runs (ki-0001/ki-0002) because a client or entry node's OWN
//! resolver traffic (for example timesyncd's NTP-pool lookup) reaches an
//! off-tunnel resolver. The generation-scoped killswitch and DNS redirect
//! are applied too late and torn down too eagerly to close that class. The
//! adopted specification (lab/ki0001-floor/B/STEP1_SPEC.md, "Exact proposed
//! policy") fixes a generation-INDEPENDENT floor: a reserved table, one
//! base chain at `output` priority -300 — before the `-100` destination NAT
//! redirect and the priority-0 killswitch — that drops every locally
//! generated UDP/TCP 53/853 packet except the three reviewed loopback
//! resolver endpoints on `lo`, port 53 only.
//!
//! # The reviewed policy (STEP1_SPEC.md:18-27)
//!
//! ```nft
//! table inet rustynet_protected_dns {
//!     chain origin_dns {
//!         type filter hook output priority -300; policy accept;
//!         oifname "lo" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return
//!         oifname "lo" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return
//!         udp dport { 53, 853 } counter drop
//!         tcp dport { 53, 853 } counter drop
//!     }
//! }
//! ```
//!
//! `return` under the chain's `policy accept` ends only THIS base chain; it
//! grants no exemption from any other base chain. The allowance is an
//! endpoint+port+interface tuple — not all of 127/8, not all loopback
//! traffic, not loopback 853 (STEP1_SPEC.md:30). The floor never depends on
//! a generation number, so generation pruning (`prune_owned_tables`,
//! phase10.rs:4172-4198) never selects it: the sweep owns `inet` tables
//! named `rustynet_g*` and `ip` tables named `rustynet_nat_g*`, and
//! [`FLOOR_TABLE`] matches neither prefix — proven by
//! [`is_floor_table`] and its test.
//!
//! # Replace idiom (binding review finding F2)
//!
//! REVIEW-B-glm53-20261105.md F2: a bare add-form `table … { … }` block is
//! ADDITIVE on an existing table — it would append duplicate rules and let
//! stale exemption text survive. [`render_floor_install_batch`] therefore
//! emits, in ONE nft transaction (a single batch is atomic: it either fully
//! applies or leaves the previous ruleset untouched):
//!
//! 1. `table inet rustynet_protected_dns` — declare-if-absent, so the next
//!    statement can never fail on a missing table;
//! 2. `delete table inet rustynet_protected_dns` — drop any prior copy,
//!    reviewed or stale;
//! 3. the full add-form table with the chain and the four rule groups.
//!
//! This works on every nft version (no `destroy` command needed), never
//! publishes an empty accept-policy chain, and is idempotent.
//!
//! # FLOOR_SCOPE_NOTE — what step 1 does NOT cover
//!
//! (STEP1_SPEC.md, "Paths covered and excluded". Nobody may read this
//! module as closing ki-0001 by itself.)
//!
//! - **DoH** — DNS inside HTTPS on port 443 is NOT classified; a
//!   DoH client is unaffected by this floor.
//! - **Arbitrary-port DNS** — a resolver on a non-53/853 port is NOT
//!   classified (the local `127.0.0.1:53535` redirect target is
//!   deliberately outside the drop classifier).
//! - **`::1` resolver** — there is NO IPv6 loopback exception; a configured
//!   IPv6-only local resolver would break and needs an explicit
//!   owner-reviewed endpoint policy. IPv4 exceptions are the only ones.
//! - **FORWARD path** — the floor hooks `output` only; an exit's FORWARD
//!   chain still forwards an unprotected peer's DNS. The original lab stage
//!   must keep failing in that case — the check stays exactly as strict.
//! - Step 1 also does not touch LLMNR/mDNS, container/other-netns
//!   forwarding, or the CAP_NET_ADMIN boundary (STEP1_SPEC.md:42), and it
//!   ships no wiring: installation ordering, rollback/`force_fail_closed`
//!   survival, helper admission and boot integration are slice 2.

use std::fmt;

/// nftables family of the floor table. `inet` covers IPv4 and IPv6 in one
/// table so the drops catch both (STEP1_SPEC.md:16,42).
pub const FLOOR_TABLE_FAMILY: &str = "inet";

/// Reserved, generation-independent floor table name
/// (STEP1_SPEC.md:16). Deliberately NOT under the `rustynet_g*` /
/// `rustynet_nat_g*` prefixes `prune_owned_tables` owns (phase10.rs:4178),
/// so generation pruning can never delete the floor.
pub const FLOOR_TABLE: &str = "rustynet_protected_dns";

/// The single base chain of the floor table (STEP1_SPEC.md:20).
pub const FLOOR_CHAIN: &str = "origin_dns";

/// Netfilter hook the floor registers at (STEP1_SPEC.md:21). Locally
/// generated traffic only — the FORWARD path is out of scope (FLOOR_SCOPE_NOTE).
pub const FLOOR_HOOK: &str = "output";

/// Hook priority (STEP1_SPEC.md:21). `-300` precedes the `-100` dstnat DNS
/// redirect and the priority-0 killswitch without sharing a priority with
/// either, so the reviewed loopback exceptions are observed pre-redirect
/// and no equal-priority registration-order tie exists.
pub const FLOOR_PRIORITY: i32 = -300;

/// How `nft list` renders [`FLOOR_PRIORITY`] on kernels whose nft prints
/// symbolic priority names: `raw` is NF_IP_PRI_RAW, i.e. exactly `-300`.
/// Listings may carry either spelling; the install batch always installs
/// the numeric form. No other symbolic name is accepted.
const FLOOR_PRIORITY_LISTING_ALIAS: &str = "raw";

/// Base-chain policy (STEP1_SPEC.md:21). `accept`, so the floor only ever
/// ADDS drops for 53/853; `policy drop` would be a full output killswitch
/// and is rejected by [`FloorViolation::WrongPolicy`].
pub const FLOOR_POLICY: &str = "accept";

/// The reviewed loopback resolver endpoints (STEP1_SPEC.md:22-23):
/// 127.0.0.1 (rustynet resolver / plain loopback), 127.0.0.53 and
/// 127.0.0.54 (systemd-resolved stub and extra stub). The exception is
/// this endpoint list AND `oifname "lo"` AND destination port 53 ONLY —
/// never 127/8, never 853, never without the interface match.
pub const FLOOR_LOOPBACK_ENDPOINTS: &[&str] = &["127.0.0.1", "127.0.0.53", "127.0.0.54"];

/// Destination ports the floor drops (STEP1_SPEC.md:24-25), for BOTH udp
/// and tcp. 53 = classic DNS, 853 = DoT/DoQ. Loopback exceptions carry port
/// 53 only; loopback 853 is dropped.
pub const FLOOR_DROP_PORTS: &[u16] = &[53, 853];

/// Chain header line of the floor base chain, exactly as nft prints and
/// installs it (STEP1_SPEC.md:21).
const CHAIN_HEADER_LINE: &str = "type filter hook output priority -300; policy accept;";

/// Rule group 1 (STEP1_SPEC.md:22): loopback UDP exception — reviewed
/// endpoints on `lo`, port 53 only, verdict `return`.
const RULE_LOOPBACK_UDP_RETURN: &str =
    "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return";

/// Rule group 2 (STEP1_SPEC.md:23): loopback TCP exception — same tuple.
const RULE_LOOPBACK_TCP_RETURN: &str =
    "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return";

/// Rule group 3 (STEP1_SPEC.md:24): family-independent UDP drop for the
/// reviewed ports. `counter` renders as `counter packets N bytes M` in a
/// listing; the verifier tolerates ONLY that numeric difference.
const RULE_UDP_DROP: &str = "udp dport { 53, 853 } counter drop";

/// Rule group 4 (STEP1_SPEC.md:25): family-independent TCP drop.
const RULE_TCP_DROP: &str = "tcp dport { 53, 853 } counter drop";

/// The four rule groups in reviewed evaluation order. Order matters: the
/// exceptions MUST precede the drops, and the drops MUST be the terminal
/// rules — a reorder is a [`FloorViolation::RuleOrder`] failure, never a
/// cosmetic difference.
const FLOOR_RULE_LINES: [&str; 4] = [
    RULE_LOOPBACK_UDP_RETURN,
    RULE_LOOPBACK_TCP_RETURN,
    RULE_UDP_DROP,
    RULE_TCP_DROP,
];

/// A typed, fail-closed verdict from [`assert_effective_floor`]. Every
/// label returned by [`FloorViolation::as_str`] is STABLE (operators and
/// later slices may match on it); new variants may be added, existing
/// labels never renamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorViolation {
    /// The listing is empty or whitespace-only.
    EmptyListing,
    /// The listing is structurally truncated or unparseable as an
    /// `nft list table` dump: missing braces, a mangled header, or trailing
    /// structure that never closes. Fail closed — never `Ok` on text the
    /// checker cannot fully walk.
    TruncatedListing,
    /// The table family is not [`FLOOR_TABLE_FAMILY`] (for example `ip`).
    WrongFamily { saw: String },
    /// The table name is not [`FLOOR_TABLE`] (for example a generation
    /// table `rustynet_g1`).
    WrongTable { saw: String },
    /// The [`FLOOR_CHAIN`] chain is absent entirely — nothing enforces the
    /// floor even if the table exists.
    MissingChain,
    /// A chain other than [`FLOOR_CHAIN`] (or a second copy of it) exists
    /// in the floor table.
    ExtraChain { saw: String },
    /// A non-chain object (set, map, flowtable) or any other content sits
    /// in the table outside the reviewed chain, or content follows the
    /// table's closing brace.
    ExtraObject { saw: String },
    /// The base-chain header does not state the reviewed
    /// `type filter hook output` shape (wrong hook, wrong chain type, or a
    /// header the checker cannot parse into that shape).
    WrongHook { saw: String },
    /// The base-chain priority is not [`FLOOR_PRIORITY`].
    WrongPriority { saw: String },
    /// The base-chain policy is not [`FLOOR_POLICY`] — for example
    /// `policy drop`.
    WrongPolicy { saw: String },
    /// One of the four reviewed rule groups ([`FLOOR_RULE_LINES`]) is
    /// absent — including a drop narrowed so it no longer matches the
    /// reviewed text.
    MissingRule { expected: &'static str },
    /// A rule beyond the reviewed four is present.
    ExtraRule { saw: String },
    /// The same four rules appear in a different evaluation order.
    RuleOrder,
    /// A loopback exception is wider than reviewed: an address outside
    /// [`FLOOR_LOOPBACK_ENDPOINTS`], a `127.0.0.0/8`-style range, port 853
    /// in the exception, a missing `oifname "lo"` match, or an `ip6`
    /// (for example `::1`) address.
    WidenedException { saw: String },
    /// An exemption the reviewed policy never contains: an `accept`
    /// verdict, `ct state`, `meta skuid`, a source-port (`sport`) match,
    /// `iifname`, a tunnel/mesh-interface allowance, or an `ip saddr` match.
    ForbiddenExemption { saw: String },
}

impl FloorViolation {
    /// Stable machine label for logs/metrics. Never rename.
    pub fn as_str(&self) -> &'static str {
        match self {
            FloorViolation::EmptyListing => "floor_listing_empty",
            FloorViolation::TruncatedListing => "floor_listing_truncated",
            FloorViolation::WrongFamily { .. } => "floor_wrong_family",
            FloorViolation::WrongTable { .. } => "floor_wrong_table",
            FloorViolation::MissingChain => "floor_missing_chain",
            FloorViolation::ExtraChain { .. } => "floor_extra_chain",
            FloorViolation::ExtraObject { .. } => "floor_extra_object",
            FloorViolation::WrongHook { .. } => "floor_wrong_hook",
            FloorViolation::WrongPriority { .. } => "floor_wrong_priority",
            FloorViolation::WrongPolicy { .. } => "floor_wrong_policy",
            FloorViolation::MissingRule { .. } => "floor_missing_rule",
            FloorViolation::ExtraRule { .. } => "floor_extra_rule",
            FloorViolation::RuleOrder => "floor_rule_order",
            FloorViolation::WidenedException { .. } => "floor_exception_widened",
            FloorViolation::ForbiddenExemption { .. } => "floor_forbidden_exemption",
        }
    }
}

impl fmt::Display for FloorViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let saw = match self {
            FloorViolation::EmptyListing
            | FloorViolation::TruncatedListing
            | FloorViolation::MissingChain
            | FloorViolation::RuleOrder => "",
            FloorViolation::WrongFamily { saw }
            | FloorViolation::WrongTable { saw }
            | FloorViolation::ExtraChain { saw }
            | FloorViolation::ExtraObject { saw }
            | FloorViolation::WrongHook { saw }
            | FloorViolation::WrongPriority { saw }
            | FloorViolation::WrongPolicy { saw }
            | FloorViolation::ExtraRule { saw }
            | FloorViolation::WidenedException { saw }
            | FloorViolation::ForbiddenExemption { saw } => saw.as_str(),
            FloorViolation::MissingRule { expected } => expected,
        };
        write!(f, "{}: {}", self.as_str(), saw)
    }
}

/// Render the EXACT nft batch (one atomic transaction, deterministic text)
/// that installs the floor table or REPLACES any prior copy of it. The
/// F2-binding idiom: declare-if-absent, `delete table`, then the full
/// add-form table (see the module docs). The text is built ONLY from the
/// compile-time constants above — there is no parameterised table name,
/// interface, address or port, and callers cannot inject any nft text.
pub fn render_floor_install_batch() -> String {
    let mut batch = String::new();
    batch.push_str("table ");
    batch.push_str(FLOOR_TABLE_FAMILY);
    batch.push(' ');
    batch.push_str(FLOOR_TABLE);
    batch.push('\n');
    batch.push_str("delete table ");
    batch.push_str(FLOOR_TABLE_FAMILY);
    batch.push(' ');
    batch.push_str(FLOOR_TABLE);
    batch.push('\n');
    batch.push_str("table ");
    batch.push_str(FLOOR_TABLE_FAMILY);
    batch.push(' ');
    batch.push_str(FLOOR_TABLE);
    batch.push_str(" {\n\tchain ");
    batch.push_str(FLOOR_CHAIN);
    batch.push_str(" {\n\t\t");
    batch.push_str(CHAIN_HEADER_LINE);
    batch.push('\n');
    for rule in FLOOR_RULE_LINES {
        batch.push_str("\t\t");
        batch.push_str(rule);
        batch.push('\n');
    }
    batch.push_str("\t}\n}\n");
    batch
}

/// Render the EXACT nft batch (one atomic transaction) that deliberately
/// removes the floor table: declare-if-absent so the `delete` can never
/// fail on an already-absent table, then `delete table`.
///
/// LIFETIME CONTRACT (slice 2 wiring, NOT this module): the floor is NEVER
/// removed by generation pruning, rollback, `force_fail_closed`, failed
/// applies, backend recovery, daemon restarts or crash recovery. This batch
/// exists ONLY for a successful, intentional transition to unprotected
/// operation AFTER protected routes and backend use have been withdrawn
/// (STEP1_SPEC.md:50). Nothing in slice 1 calls it.
pub fn render_floor_remove_batch() -> String {
    let mut batch = String::new();
    batch.push_str("table ");
    batch.push_str(FLOOR_TABLE_FAMILY);
    batch.push(' ');
    batch.push_str(FLOOR_TABLE);
    batch.push('\n');
    batch.push_str("delete table ");
    batch.push_str(FLOOR_TABLE_FAMILY);
    batch.push(' ');
    batch.push_str(FLOOR_TABLE);
    batch.push('\n');
    batch
}

/// True ONLY for the fixed floor table identity
/// ([`FLOOR_TABLE_FAMILY`], [`FLOOR_TABLE`]) — an exact match, never a
/// prefix. `rustynet_g1`-style generation tables are NOT the floor; the
/// floor is not any generation.
pub fn is_floor_table(family: &str, name: &str) -> bool {
    family == FLOOR_TABLE_FAMILY && name == FLOOR_TABLE
}

/// Strict, whole-structure, fail-closed verification of the text printed by
/// `nft list table inet rustynet_protected_dns` (see the caller
/// contract below). `Ok(())` means the listing is EXACTLY the reviewed
/// floor: table header, the one base chain, the reviewed
/// `type filter hook output priority -300; policy accept;` header and the
/// four rule groups in order — with ONLY these tolerated differences from
/// the canonical text, each harmless on real nft output and each pinned
/// by a test:
///
/// * numeric counter values (`counter packets N bytes M` ≡ the installed
///   `counter`);
/// * the `raw` symbolic priority alias (`priority raw;` ≡
///   `priority -300;`, and no other symbolic name);
/// * whitespace: leading/trailing whitespace per line, blank lines
///   anywhere, and intra-line whitespace runs collapsed to one space
///   (via `str::trim`/`str::split_whitespace`, so Unicode whitespace such
///   as U+00A0 collapses too) — indentation and blank lines are this
///   item, not a separate one;
/// * a `{` glued to the chain name on the chain line
///   (`chain origin_dns{` ≡ `chain origin_dns {`). A glued brace is NOT
///   tolerated on the table header line, whose `{` must be a separate
///   token.
///
/// Anything else — wrong family/table, extra or missing chain, extra
/// objects, wrong hook/priority/policy, a missing or doubled `;`
/// terminator on the header's priority or policy field, a missing drop,
/// an extra or reordered rule, a widened exception, a forbidden exemption,
/// or a truncated/empty/unparseable listing — is a typed
/// [`FloorViolation`]. Never returns `Ok` on text it cannot fully walk.
///
/// # Caller contract
///
/// Callers MUST pass the output of `nft list table
/// inet rustynet_protected_dns` in nft's default numeric-port rendering
/// (`nft -nn list table ...` prints the same text except that the priority
/// appears as `-300` where plain nft prints the alias `raw`; both are
/// accepted): the reviewed rules compare `dport 53` / `dport 853` by number,
/// so a listing rendered with service names (nft's opt-in `-S` flag:
/// `domain`, `domain-s`) does not match the reviewed text and is
/// REJECTED, fail closed ([`FloorViolation::MissingRule`]). And never
/// `nft -a list table ...`: handle annotations (`# handle N` appended to
/// the table, chain and rule lines) are extra text this verifier does not
/// parse, so an `nft -a` listing is REJECTED, fail closed
/// ([`FloorViolation::TruncatedListing`]).
pub fn assert_effective_floor(listing: &str) -> Result<(), FloorViolation> {
    let saw = |line: &str| line.trim().to_owned();
    let mut lines = listing.lines().map(str::trim).filter(|l| !l.is_empty());

    // Table header: `table <family> <name> {`
    let Some(header) = lines.next() else {
        return Err(FloorViolation::EmptyListing);
    };
    let header_tokens: Vec<&str> = header.split_whitespace().collect();
    let (family, name) = match header_tokens.as_slice() {
        ["table", family, name, "{"] => (*family, *name),
        _ => return Err(FloorViolation::TruncatedListing),
    };
    if family != FLOOR_TABLE_FAMILY {
        return Err(FloorViolation::WrongFamily {
            saw: family.to_owned(),
        });
    }
    if name != FLOOR_TABLE {
        return Err(FloorViolation::WrongTable {
            saw: name.to_owned(),
        });
    }

    // Where the walk currently is. The chain's closing brace and the
    // table's closing brace are the same text, so the stage — not the line
    // alone — decides which object a `}` closes.
    #[derive(PartialEq)]
    enum Stage {
        /// Inside the table, before or after the reviewed chain.
        TableBody,
        /// Directly after `chain origin_dns {`: the base-chain header line.
        ChainHeader,
        /// Rule lines until the chain's `}`.
        ChainRules,
        /// The chain closed; only the table's `}` may follow.
        AfterChain,
        /// The table closed; only blank lines may follow.
        Done,
    }
    let mut stage = Stage::TableBody;
    let mut header_verified = false;
    let mut rule_lines: Vec<String> = Vec::new();
    for line in lines {
        let chain_line_name = || {
            line.strip_prefix("chain ")
                .and_then(|rest| rest.trim().strip_suffix('{').map(str::trim))
        };
        match stage {
            Stage::TableBody | Stage::AfterChain => {
                if line == "}" {
                    stage = Stage::Done;
                    continue;
                }
                if let Some(name) = chain_line_name() {
                    if name == FLOOR_CHAIN && stage == Stage::TableBody && !header_verified {
                        stage = Stage::ChainHeader;
                        continue;
                    }
                    return Err(FloorViolation::ExtraChain { saw: saw(line) });
                }
                return Err(FloorViolation::ExtraObject { saw: saw(line) });
            }
            Stage::ChainHeader => {
                if line == "}" {
                    // An empty chain: no reviewed base-chain header at all.
                    stage = Stage::AfterChain;
                    continue;
                }
                let tokens: Vec<&str> = line.split_whitespace().collect();
                let (kind, hook, priority, policy) = match tokens.as_slice() {
                    [
                        "type",
                        kind,
                        "hook",
                        hook,
                        "priority",
                        priority,
                        "policy",
                        policy,
                    ] => (*kind, *hook, *priority, *policy),
                    _ => return Err(FloorViolation::WrongHook { saw: saw(line) }),
                };
                if kind != "filter" || hook != FLOOR_HOOK {
                    return Err(FloorViolation::WrongHook { saw: saw(line) });
                }
                // Each field carries EXACTLY ONE `;` terminator, glued to
                // the value — the real nft print shape is `priority raw;`
                // / `priority -300;` / `policy accept;`, and real nft
                // ALWAYS prints both terminators. Zero terminators is not
                // nft's print shape either and is rejected here; more
                // than one (`;;`) keeps a leftover `;` after this single
                // strip and fails the exact comparison below.
                let priority = match priority.strip_suffix(';') {
                    Some(stripped) => stripped,
                    None => {
                        return Err(FloorViolation::WrongPriority { saw: saw(line) });
                    }
                };
                if priority != FLOOR_PRIORITY.to_string()
                    && priority != FLOOR_PRIORITY_LISTING_ALIAS
                {
                    return Err(FloorViolation::WrongPriority { saw: saw(line) });
                }
                let policy = match policy.strip_suffix(';') {
                    Some(stripped) => stripped,
                    None => {
                        return Err(FloorViolation::WrongPolicy { saw: saw(line) });
                    }
                };
                if policy != FLOOR_POLICY {
                    return Err(FloorViolation::WrongPolicy { saw: saw(line) });
                }
                header_verified = true;
                stage = Stage::ChainRules;
                continue;
            }
            Stage::ChainRules => {
                if line == "}" {
                    stage = Stage::AfterChain;
                    continue;
                }
                rule_lines.push(line.to_owned());
            }
            Stage::Done => {
                // Anything non-blank after the table's closing brace is
                // content beyond the reviewed table.
                return Err(FloorViolation::ExtraObject { saw: saw(line) });
            }
        }
    }
    if stage != Stage::Done {
        return Err(FloorViolation::TruncatedListing);
    }
    if !header_verified {
        return Err(FloorViolation::MissingChain);
    }

    // Rule groups: exact ordered match, counters tolerated numerically.
    let normalized: Vec<String> = rule_lines.iter().map(|l| normalize_rule_line(l)).collect();
    let expected: Vec<String> = FLOOR_RULE_LINES
        .iter()
        .map(|r| normalize_rule_line(r))
        .collect();
    if normalized.len() < expected.len() {
        // The first expected rule absent from the listing is the missing one.
        for rule in &expected {
            if !normalized.contains(rule) {
                return Err(FloorViolation::MissingRule {
                    expected: static_rule_for(rule),
                });
            }
        }
        return Err(FloorViolation::MissingRule {
            expected: RULE_UDP_DROP,
        });
    }
    if normalized.len() > expected.len() {
        // The surplus rule is classified, not just counted: an extra
        // accept/exemption rule is named as forbidden even when the four
        // reviewed rules are all present and correct.
        let extra = match normalized.get(expected.len()) {
            Some(extra) => extra.clone(),
            None => String::new(),
        };
        return Err(match classify_rule_mismatch(&extra) {
            FloorViolation::ExtraRule { saw } => FloorViolation::ExtraRule { saw },
            specific => specific,
        });
    }
    for (got, want) in normalized.iter().zip(expected.iter()) {
        if got != want {
            // Pure reorder of the same four rules.
            if same_rules_different_order(&normalized, &expected) {
                return Err(FloorViolation::RuleOrder);
            }
            // What replaced the reviewed rule at this position decides the
            // label: a forbidden exemption or a widened exception is named
            // as such, not as a missing rule.
            match classify_rule_mismatch(got) {
                FloorViolation::ExtraRule { .. } => {}
                specific => return Err(specific),
            }
            // Otherwise the reviewed rule at this position is simply absent
            // (narrowed drop, mangled text) if nothing else carries it.
            if !normalized.contains(want) {
                return Err(FloorViolation::MissingRule {
                    expected: static_rule_for(want),
                });
            }
            return Err(FloorViolation::ExtraRule { saw: got.clone() });
        }
    }
    Ok(())
}

/// Map `counter packets <N> bytes <M>` to `counter` (the installed form);
/// every other byte of the line is compared verbatim after whitespace
/// normalization.
fn normalize_rule_line(line: &str) -> String {
    fn is_all_digits(value: &str) -> bool {
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut out: Vec<&str> = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        let counter_run = tokens.len() >= index + 5
            && tokens.get(index).copied() == Some("counter")
            && tokens.get(index + 1).copied() == Some("packets")
            && tokens.get(index + 3).copied() == Some("bytes")
            && tokens.get(index + 2).copied().is_some_and(is_all_digits)
            && tokens.get(index + 4).copied().is_some_and(is_all_digits);
        if counter_run {
            out.push("counter");
            index += 5;
            continue;
        }
        if let Some(token) = tokens.get(index).copied() {
            out.push(token);
        }
        index += 1;
    }
    out.join(" ")
}

/// The `&'static str` form of an expected rule (for `MissingRule`).
fn static_rule_for(normalized: &str) -> &'static str {
    for rule in FLOOR_RULE_LINES {
        if normalize_rule_line(rule) == normalized {
            return rule;
        }
    }
    RULE_UDP_DROP
}

/// True when both lists hold the same rule multiset (same rules, different
/// evaluation order).
fn same_rules_different_order(got: &[String], expected: &[String]) -> bool {
    let mut got_sorted = got.to_vec();
    let mut expected_sorted = expected.to_vec();
    got_sorted.sort();
    expected_sorted.sort();
    got_sorted == expected_sorted
}

/// Classify a rule that differs from the reviewed text at its position:
/// a forbidden exemption marker wins over an exception-shape mismatch,
/// which wins over the generic extra-rule verdict. Every outcome is `Err`
/// — the classifier only picks the label.
fn classify_rule_mismatch(got: &str) -> FloorViolation {
    let saw = got.to_owned();
    let tokens: Vec<&str> = got.split_whitespace().collect();
    let is_accept_verdict = tokens.last() == Some(&"accept");
    let has_forbidden_marker = tokens.iter().any(|token| {
        matches!(
            *token,
            "ct" | "skuid" | "iifname" | "saddr" | "wireguard" | "tunnel"
        )
    }) || tokens.contains(&"sport")
        || tokens.windows(2).any(|pair| {
            pair == ["ct", "state"] || pair == ["meta", "skuid"] || pair == ["ip", "saddr"]
        });
    if is_accept_verdict || has_forbidden_marker {
        return FloorViolation::ForbiddenExemption { saw };
    }
    let ends_with_return = tokens.last() == Some(&"return");
    let looks_like_exception = tokens.contains(&"oifname")
        || tokens
            .windows(2)
            .any(|pair| pair == ["ip", "daddr"] || pair == ["ip6", "daddr"]);
    if ends_with_return || looks_like_exception {
        return FloorViolation::WidenedException { saw };
    }
    FloorViolation::ExtraRule { saw }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_INSTALL_BATCH: &str = "table inet rustynet_protected_dns\n\
delete table inet rustynet_protected_dns\n\
table inet rustynet_protected_dns {\n\
\tchain origin_dns {\n\
\t\ttype filter hook output priority -300; policy accept;\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return\n\
\t\tudp dport { 53, 853 } counter drop\n\
\t\ttcp dport { 53, 853 } counter drop\n\
\t}\n\
}\n";

    const GOLDEN_REMOVE_BATCH: &str =
        "table inet rustynet_protected_dns\ndelete table inet rustynet_protected_dns\n";

    /// The canonical positive listing: nft's own print shape for the
    /// installed floor, with per-rule counter values.
    fn good_listing() -> String {
        "table inet rustynet_protected_dns {\n\
\tchain origin_dns {\n\
\t\ttype filter hook output priority -300; policy accept;\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return\n\
\t\tudp dport { 53, 853 } counter packets 1024 bytes 71680 drop\n\
\t\ttcp dport { 53, 853 } counter packets 3 bytes 220 drop\n\
\t}\n\
}\n"
        .to_owned()
    }

    /// Build a listing body with arbitrary rule lines (tab-indented).
    fn listing_with_rules(rules: &[&str]) -> String {
        let mut out = String::from(
            "table inet rustynet_protected_dns {\n\tchain origin_dns {\n\t\ttype filter hook output priority -300; policy accept;\n",
        );
        for rule in rules {
            out.push_str("\t\t");
            out.push_str(rule);
            out.push('\n');
        }
        out.push_str("\t}\n}\n");
        out
    }

    #[test]
    fn install_batch_is_the_exact_f2_replace_idiom() {
        let batch = render_floor_install_batch();
        assert_eq!(batch, GOLDEN_INSTALL_BATCH);
        // F2 structure, in order, in ONE batch: declare-if-absent, delete,
        // full add-form table.
        let declare = "table inet rustynet_protected_dns\n";
        let delete = "delete table inet rustynet_protected_dns\n";
        assert!(batch.starts_with(declare));
        assert!(batch[declare.len()..].starts_with(delete));
        // The add-form table block follows and is the LAST statement.
        assert!(batch.ends_with("}\n}\n"));
        // Exactly one delete and exactly one add-form block: replace, never
        // append.
        assert_eq!(batch.matches("delete table").count(), 1);
        assert_eq!(batch.matches("chain origin_dns {").count(), 1);
    }

    #[test]
    fn remove_batch_is_declare_then_delete_only() {
        assert_eq!(render_floor_remove_batch(), GOLDEN_REMOVE_BATCH);
    }

    #[test]
    fn renderers_are_deterministic() {
        assert_eq!(render_floor_install_batch(), render_floor_install_batch());
        assert_eq!(render_floor_remove_batch(), render_floor_remove_batch());
    }

    #[test]
    fn spec_constants_are_pinned() {
        assert_eq!(FLOOR_TABLE_FAMILY, "inet");
        assert_eq!(FLOOR_TABLE, "rustynet_protected_dns");
        assert_eq!(FLOOR_CHAIN, "origin_dns");
        assert_eq!(FLOOR_HOOK, "output");
        assert_eq!(FLOOR_PRIORITY, -300);
        assert_eq!(FLOOR_POLICY, "accept");
        assert_eq!(
            FLOOR_LOOPBACK_ENDPOINTS,
            &["127.0.0.1", "127.0.0.53", "127.0.0.54"]
        );
        assert_eq!(FLOOR_DROP_PORTS, &[53u16, 853]);
        // The golden rule text carries exactly the reviewed endpoints,
        // port 53 only, on `lo`, and the reviewed drop ports.
        for rule in [RULE_LOOPBACK_UDP_RETURN, RULE_LOOPBACK_TCP_RETURN] {
            assert!(rule.contains("oifname \"lo\""));
            assert!(rule.contains("dport 53 return"));
            for endpoint in FLOOR_LOOPBACK_ENDPOINTS {
                assert!(rule.contains(endpoint));
            }
            assert!(!rule.contains("853"));
        }
        for rule in [RULE_UDP_DROP, RULE_TCP_DROP] {
            assert!(rule.contains("dport { 53, 853 }"));
            assert!(rule.contains("counter drop"));
        }
    }

    #[test]
    fn effective_floor_listing_with_counter_values_passes() {
        assert_eq!(assert_effective_floor(&good_listing()), Ok(()));
    }

    #[test]
    fn real_kernel_listing_is_accepted() {
        // Verbatim `nft list table inet rustynet_protected_dns` output after
        // loading the golden install batch in a fresh `unshare -Urnm`
        // namespace on the lane host (nft prints the symbolic priority
        // alias `raw` for -300 and zero-valued counters).
        let listing = "table inet rustynet_protected_dns {\n\
\tchain origin_dns {\n\
\t\ttype filter hook output priority raw; policy accept;\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return\n\
\t\tudp dport { 53, 853 } counter packets 0 bytes 0 drop\n\
\t\ttcp dport { 53, 853 } counter packets 0 bytes 0 drop\n\
\t}\n\
}\n";
        assert_eq!(assert_effective_floor(listing), Ok(()));
    }

    #[test]
    fn effective_floor_listing_with_bare_counters_passes() {
        // The spec's install form (`counter`, no values) must also verify.
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter drop",
            "tcp dport { 53, 853 } counter drop",
        ]);
        assert_eq!(assert_effective_floor(&listing), Ok(()));
    }

    #[test]
    fn listing_tolerates_indentation_and_blank_lines_only() {
        let listing = "\n\
             table inet rustynet_protected_dns {\n\
             \n\
                    chain origin_dns {\n\
             \t\t\ttype filter hook output priority -300; policy accept;\n\
             \t\t\t  oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return\n\
             \t\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return\n\
             \n\
             \t\t\tudp dport { 53, 853 } counter packets 0 bytes 0 drop\n\
             \t\t\ttcp dport { 53, 853 } counter packets 9 bytes 640 drop\n\
             \t}\n\
             \n\
             }\n\
             \n";
        assert_eq!(assert_effective_floor(listing), Ok(()));
    }

    #[test]
    fn tolerated_cosmetic_differences_are_pinned() {
        // L2 closure: the doc comment on assert_effective_floor enumerates
        // every difference from the canonical text the verifier TOLERATES
        // today. This test PINS that set as "tolerated, harmless on real
        // nft output": the `raw` priority alias, per-line and intra-line
        // whitespace runs (including the Unicode whitespace
        // str::trim/split_whitespace accept, here U+00A0), blank lines
        // anywhere, and a `{` glued to the chain name on the chain line.
        // None of these widens what `Ok(())` means structurally; the test
        // fails loudly if any tolerance is removed OR quietly widened.
        let listing = "table inet rustynet_protected_dns {\n\
        \tchain origin_dns{\n\
        \t\ttype\u{00a0}filter hook output   priority raw; policy accept;\n\
        \n\
        \t\toifname \"lo\"  ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return\n\
        \t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53\u{00a0}return\n\
        \t\tudp dport { 53, 853 } counter packets 0 bytes 0 drop\n\
        \t\ttcp dport { 53, 853 } counter drop\n\
        \t}\n\
        \n\
        }\n";
        assert_eq!(assert_effective_floor(listing), Ok(()));
    }

    #[test]
    fn empty_listing_is_rejected() {
        assert_eq!(
            assert_effective_floor(""),
            Err(FloorViolation::EmptyListing)
        );
        assert_eq!(
            assert_effective_floor("   \n\t\n"),
            Err(FloorViolation::EmptyListing)
        );
    }

    #[test]
    fn truncated_listing_is_rejected() {
        let good = good_listing();
        // Missing final closing brace of the table.
        let cut = &good[..good.len() - 2];
        assert_eq!(
            assert_effective_floor(cut),
            Err(FloorViolation::TruncatedListing)
        );
        // Only the table header line.
        assert_eq!(
            assert_effective_floor("table inet rustynet_protected_dns {"),
            Err(FloorViolation::TruncatedListing)
        );
        // Cut mid-chain, before any rule.
        assert_eq!(
            assert_effective_floor(
                "table inet rustynet_protected_dns {\n\tchain origin_dns {\n\t\ttype filter hook output priority -300; policy accept;\n"
            ),
            Err(FloorViolation::TruncatedListing)
        );
    }

    #[test]
    fn wrong_family_is_rejected() {
        let listing = good_listing().replacen("table inet", "table ip", 1);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongFamily { saw: "ip".into() })
        );
    }

    #[test]
    fn wrong_table_name_is_rejected() {
        let listing = good_listing().replacen(
            "table inet rustynet_protected_dns",
            "table inet rustynet_g1",
            1,
        );
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongTable {
                saw: "rustynet_g1".into()
            })
        );
    }

    #[test]
    fn missing_chain_is_rejected() {
        let listing = "table inet rustynet_protected_dns {\n}\n";
        assert_eq!(
            assert_effective_floor(listing),
            Err(FloorViolation::MissingChain)
        );
    }

    #[test]
    fn extra_chain_is_rejected() {
        let mut listing = good_listing();
        let extra =
            "\tchain stray {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n";
        listing.insert_str(listing.len() - 2, extra);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ExtraChain {
                saw: "chain stray {".into()
            })
        );
        // A duplicate of the reviewed chain is equally extra.
        let mut duplicate = good_listing();
        let dup = "\tchain origin_dns {\n\t\ttype filter hook output priority -300; policy accept;\n\t}\n";
        duplicate.insert_str(duplicate.len() - 2, dup);
        assert_eq!(
            assert_effective_floor(&duplicate),
            Err(FloorViolation::ExtraChain {
                saw: "chain origin_dns {".into()
            })
        );
    }

    #[test]
    fn extra_non_chain_object_is_rejected() {
        for object in [
            "set allowlist {",
            "map ports { type inet_service : mark; }",
            "flowtable f { hook ingress priority 0; devices = { lo }; }",
            "whatever garbage",
        ] {
            let mut listing = good_listing();
            listing.insert_str(listing.len() - 2, &format!("\t{object}\n"));
            assert_eq!(
                assert_effective_floor(&listing),
                Err(FloorViolation::ExtraObject {
                    saw: object.to_owned()
                }),
                "object {object} must be rejected as extra content"
            );
        }
        // Content after the table's closing brace is equally extra.
        let trailing = format!("{}table inet other {{\n}}\n", good_listing());
        assert_eq!(
            assert_effective_floor(&trailing),
            Err(FloorViolation::ExtraObject {
                saw: "table inet other {".into()
            })
        );
    }

    #[test]
    fn wrong_hook_is_rejected() {
        let listing = good_listing().replacen("hook output", "hook input", 1);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongHook {
                saw: "type filter hook input priority -300; policy accept;".into()
            })
        );
        // A nat chain at the same hook is a wrong base-chain shape.
        let listing = good_listing().replacen("type filter", "type nat", 1);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongHook {
                saw: "type nat hook output priority -300; policy accept;".into()
            })
        );
        // An unparseable header never verifies.
        let listing = good_listing().replacen(
            "type filter hook output priority -300; policy accept;",
            "policy accept;",
            1,
        );
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongHook { .. })
        ));
    }

    #[test]
    fn wrong_priority_is_rejected() {
        for priority in [
            "0", "100", "-100", "-299", "filter", "dstnat", "mangle", "raw+1",
        ] {
            let listing =
                good_listing().replacen("priority -300;", &format!("priority {priority};"), 1);
            assert_eq!(
                assert_effective_floor(&listing),
                Err(FloorViolation::WrongPriority {
                    saw: format!("type filter hook output priority {priority}; policy accept;")
                }),
                "priority {priority} must be rejected"
            );
        }
    }

    #[test]
    fn wrong_policy_drop_is_rejected() {
        let listing = good_listing().replacen("policy accept;", "policy drop;", 1);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WrongPolicy {
                saw: "type filter hook output priority -300; policy drop;".into()
            })
        );
    }

    #[test]
    fn repeated_chain_header_terminators_are_rejected() {
        // At most ONE optional `;` terminator per header field is stripped,
        // so a doubled `;;` is NOT the reviewed header text: the field keeps
        // its leftover `;` and the exact-equality check fails. Real nft
        // never prints this; accepting it would weaken the "exactly the
        // reviewed header" property.
        let cases = [
            (
                "type filter hook output priority -300;; policy accept;",
                Err(FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -300;; policy accept;".into(),
                }),
            ),
            (
                "type filter hook output priority -300; policy accept;;",
                Err(FloorViolation::WrongPolicy {
                    saw: "type filter hook output priority -300; policy accept;;".into(),
                }),
            ),
            (
                "type filter hook output priority -300;; policy accept;;",
                Err(FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -300;; policy accept;;".into(),
                }),
            ),
        ];
        for (header, expected) in cases {
            let listing = good_listing().replacen(
                "type filter hook output priority -300; policy accept;",
                header,
                1,
            );
            assert_eq!(
                assert_effective_floor(&listing),
                expected,
                "doubled header terminators in {header:?} must be rejected"
            );
        }
    }

    #[test]
    fn missing_chain_header_terminators_are_rejected() {
        // L1 closure: real nft ALWAYS prints the `;` after the priority
        // and after the policy. A listing without them is not nft's print
        // shape and is rejected fail closed with the field's precise
        // EXISTING variant — the terminator is required exactly once, not
        // zero-or-one. (This test is RED on the zero-or-one code.)
        let cases = [
            (
                "no terminator on priority",
                "type filter hook output priority -300 policy accept;",
                Err(FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -300 policy accept;".into(),
                }),
            ),
            (
                "no terminator on policy",
                "type filter hook output priority -300; policy accept",
                Err(FloorViolation::WrongPolicy {
                    saw: "type filter hook output priority -300; policy accept".into(),
                }),
            ),
            (
                "no terminator on either field",
                "type filter hook output priority -300 policy accept",
                Err(FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -300 policy accept".into(),
                }),
            ),
        ];
        for (what, header, expected) in cases {
            let listing = good_listing().replacen(
                "type filter hook output priority -300; policy accept;",
                header,
                1,
            );
            assert_eq!(
                assert_effective_floor(&listing),
                expected,
                "{what} must be rejected with its named violation"
            );
        }
    }

    #[test]
    fn lookalike_identities_are_rejected_exactly() {
        // Exact-equality pins for every identity field: a prefix-lookalike
        // (or a superstring of the reviewed value) must stay Err, each with
        // the named violation. Each case goes RED under the matching
        // `==` -> `starts_with` mutant of the field's check.
        let cases: [(&str, String, FloorViolation); 6] = [
            (
                // family mutant `family.starts_with("inet")` accepts this.
                "family inet6 lookalike",
                good_listing().replacen("table inet", "table inet6", 1),
                FloorViolation::WrongFamily {
                    saw: "inet6".into(),
                },
            ),
            (
                // Not `inet` and not a prefix of any accepted family.
                "family ip6 lookalike",
                good_listing().replacen("table inet", "table ip6", 1),
                FloorViolation::WrongFamily { saw: "ip6".into() },
            ),
            (
                // table mutant `name.starts_with(FLOOR_TABLE)` accepts this.
                "table suffix lookalike",
                good_listing().replacen(
                    "table inet rustynet_protected_dns {",
                    "table inet rustynet_protected_dns_extra {",
                    1,
                ),
                FloorViolation::WrongTable {
                    saw: "rustynet_protected_dns_extra".into(),
                },
            ),
            (
                // priority mutant `priority.starts_with("-300")` accepts this.
                "priority -3000 superstring",
                good_listing().replacen("priority -300;", "priority -3000;", 1),
                FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -3000; policy accept;".into(),
                },
            ),
            (
                // Same mutant accepts this non-numeric superstring too.
                "priority -300junk superstring",
                good_listing().replacen("priority -300;", "priority -300junk;", 1),
                FloorViolation::WrongPriority {
                    saw: "type filter hook output priority -300junk; policy accept;".into(),
                },
            ),
            (
                // policy mutant `policy.starts_with("accept")` accepts this.
                "policy acceptfoo superstring",
                good_listing().replacen("policy accept;", "policy acceptfoo;", 1),
                FloorViolation::WrongPolicy {
                    saw: "type filter hook output priority -300; policy acceptfoo;".into(),
                },
            ),
        ];
        for (what, listing, expected) in cases {
            assert_eq!(
                assert_effective_floor(&listing),
                Err(expected),
                "{what} must be rejected with its named violation"
            );
        }
    }

    #[test]
    fn chain_kind_and_hook_lookalikes_are_rejected_exactly() {
        // M1 closure of the independent review: the CHAIN identity, the
        // chain KIND and the HOOK are pinned by exact equality, exactly
        // like family/table/priority/policy above. Each case goes RED
        // under the matching `==`/`!=` -> `starts_with` mutant of its
        // field's check; the production comparisons stay exact `==`.
        // A chain whose name merely STARTS WITH `origin_dns` is not the
        // reviewed chain: it surfaces as ExtraChain (the listing's only
        // chain is not the floor's).
        let renamed = good_listing().replacen("chain origin_dns {", "chain origin_dns2 {", 1);
        assert_eq!(
            assert_effective_floor(&renamed),
            Err(FloorViolation::ExtraChain {
                saw: "chain origin_dns2 {".into()
            })
        );
        // Kind and hook lookalikes are a wrong base-chain shape and keep
        // the precise WrongHook verdict.
        for (what, header) in [
            (
                "kind lookalike filterx",
                "type filterx hook output priority -300; policy accept;",
            ),
            (
                "hook lookalike outputx",
                "type filter hook outputx priority -300; policy accept;",
            ),
            (
                "hook lookalike output2",
                "type filter hook output2 priority -300; policy accept;",
            ),
        ] {
            let listing = good_listing().replacen(
                "type filter hook output priority -300; policy accept;",
                header,
                1,
            );
            assert_eq!(
                assert_effective_floor(&listing),
                Err(FloorViolation::WrongHook {
                    saw: header.to_owned()
                }),
                "{what} must be rejected as a wrong base-chain shape"
            );
        }
    }

    #[test]
    fn handle_annotated_listing_is_rejected() {
        // Callers MUST verify the output of PLAIN
        // `nft list table inet rustynet_protected_dns`, never
        // `nft -a list table ...`: handle annotations (`# handle N`) on the
        // table/chain/rule lines are extra text the verifier does not
        // parse, and the check fails CLOSED on them (TruncatedListing —
        // the annotated table header no longer matches the four-token
        // shape). This test pins that `nft -a` output is an Err, never an
        // accepted floor.
        let listing = "table inet rustynet_protected_dns { # handle 2\n\
\tchain origin_dns { # handle 1\n\
\t\ttype filter hook output priority -300; policy accept;\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return # handle 5\n\
\t\toifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return # handle 6\n\
\t\tudp dport { 53, 853 } counter packets 0 bytes 0 drop # handle 7\n\
\t\ttcp dport { 53, 853 } counter packets 0 bytes 0 drop # handle 8\n\
\t}\n\
}\n";
        assert_eq!(
            assert_effective_floor(listing),
            Err(FloorViolation::TruncatedListing)
        );
    }

    #[test]
    fn service_name_listing_is_rejected_fail_closed() {
        // L4 closure: the verifier compares ports NUMERICALLY. A listing
        // rendered with service names (nft's opt-in `-S` flag: `domain` = 53,
        // `domain-s` = 853) is not the reviewed rule text and is rejected fail
        // closed with the precise existing variant (MissingRule for the
        // numeric drop that no longer appears).
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { domain, domain-s } counter packets 0 bytes 0 drop",
            "tcp dport { domain, domain-s } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_UDP_DROP
            })
        );
    }

    #[test]
    fn missing_udp_loopback_exception_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_LOOPBACK_UDP_RETURN
            })
        );
    }

    #[test]
    fn missing_tcp_loopback_exception_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_LOOPBACK_TCP_RETURN
            })
        );
    }

    #[test]
    fn missing_udp_drop_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_UDP_DROP
            })
        );
    }

    #[test]
    fn missing_tcp_drop_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_TCP_DROP
            })
        );
    }

    #[test]
    fn narrowed_drop_is_rejected() {
        // A drop that no longer covers 853 is not the reviewed drop.
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport 53 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::MissingRule {
                expected: RULE_TCP_DROP
            })
        ));
    }

    #[test]
    fn extra_rule_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "udp dport 42 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ExtraRule {
                saw: "udp dport 42 drop".into()
            })
        );
    }

    #[test]
    fn reordered_rules_are_rejected() {
        // Drops evaluated before the exceptions.
        let listing = listing_with_rules(&[
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::RuleOrder)
        );
    }

    #[test]
    fn widened_exception_extra_address_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54, 9.9.9.9 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WidenedException {
                saw: "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54, 9.9.9.9 } udp dport 53 return".into()
            })
        );
    }

    #[test]
    fn widened_exception_127_slash_8_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr 127.0.0.0/8 udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WidenedException { .. })
        ));
    }

    #[test]
    fn widened_exception_port_853_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport { 53, 853 } return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WidenedException { .. })
        ));
    }

    #[test]
    fn widened_exception_without_oifname_is_rejected() {
        let listing = listing_with_rules(&[
            "ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WidenedException { .. })
        ));
    }

    #[test]
    fn widened_exception_ip6_loopback_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip6 daddr ::1 udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::WidenedException { .. })
        ));
    }

    #[test]
    fn forbidden_accept_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "oifname \"rustynet0\" accept",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn forbidden_ct_state_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "ct state established,related accept",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn forbidden_skuid_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "meta skuid 0 accept",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn forbidden_sport_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "udp sport 53 accept",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn forbidden_sport_rule_without_accept_verdict_is_rejected() {
        // A `sport` rule that does NOT end in `accept` must still be named
        // as a forbidden exemption: the sport marker alone (not the
        // verdict) drives the classification, so removing the marker
        // (`tokens.contains(&"sport")` -> absent) turns this Err from
        // ForbiddenExemption into WidenedException and this test RED.
        let listing = listing_with_rules(&[
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "udp sport 5353 return",
        ]);
        assert_eq!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption {
                saw: "udp sport 5353 return".into()
            })
        );
    }

    #[test]
    fn forbidden_iifname_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "iifname \"eth0\" accept",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn forbidden_saddr_exemption_is_rejected() {
        let listing = listing_with_rules(&[
            "ip saddr 10.0.0.0/8 accept",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ]);
        assert!(matches!(
            assert_effective_floor(&listing),
            Err(FloorViolation::ForbiddenExemption { .. })
        ));
    }

    #[test]
    fn every_single_line_deletion_is_rejected() {
        let good = good_listing();
        let line_count = good.lines().count();
        for drop_index in 0..line_count {
            let mutilated: Vec<&str> = good
                .lines()
                .enumerate()
                .filter(|(index, _)| *index != drop_index)
                .map(|(_, line)| line)
                .collect();
            let listing = mutilated.join("\n");
            assert!(
                assert_effective_floor(&listing).is_err(),
                "deleting line {drop_index} must never verify:\n{listing}"
            );
        }
    }

    #[test]
    fn every_adjacent_rule_swap_is_rejected() {
        let rules = [
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } udp dport 53 return",
            "oifname \"lo\" ip daddr { 127.0.0.1, 127.0.0.53, 127.0.0.54 } tcp dport 53 return",
            "udp dport { 53, 853 } counter packets 0 bytes 0 drop",
            "tcp dport { 53, 853 } counter packets 0 bytes 0 drop",
        ];
        for swap in 0..rules.len() - 1 {
            let mut swapped = rules.to_vec();
            swapped.swap(swap, swap + 1);
            let listing = listing_with_rules(&swapped);
            assert_eq!(
                assert_effective_floor(&listing),
                Err(FloorViolation::RuleOrder),
                "swapping rules {swap} and {} must be rejected as a reorder",
                swap + 1
            );
        }
    }

    #[test]
    fn floor_table_identity_pins_the_prune_candidate_rule() {
        // The ownership predicate of phase10.rs prune_owned_tables
        // (phase10.rs:4178-4179 in LinuxCommandSystem) is COPIED here
        // verbatim purely as DOCUMENTATION of the reviewed predicate
        // text. This test does NOT detect drift: it exercises only this
        // local copy, so a future edit to phase10.rs or
        // privileged_helper.rs will NOT fail this test.
        // SLICE-2 TODO: share the predicate with phase10
        // prune_owned_tables (one helper used by both sides) when slice 2
        // wires the floor in, so drift becomes detectable.
        //   let is_owned = (family == "inet" && table.starts_with("rustynet_g"))
        //       || (family == "ip" && table.starts_with("rustynet_nat_g"));
        let prune_owned = |family: &str, table: &str| {
            (family == "inet" && table.starts_with("rustynet_g"))
                || (family == "ip" && table.starts_with("rustynet_nat_g"))
        };
        assert!(
            !prune_owned(FLOOR_TABLE_FAMILY, FLOOR_TABLE),
            "generation pruning must never select the fixed floor table"
        );
        // The privileged helper's owned-table admission
        // (privileged_helper.rs is_owned_nft_table_token: rustynet_g*,
        // rustynet_nat_g*, rustynet_tdns_*, the fixed gossip table) also
        // does NOT cover the floor name — slice 2 must add explicit
        // admission for it.
        for owned_prefix in ["rustynet_g", "rustynet_nat_g", "rustynet_tdns_"] {
            assert!(!FLOOR_TABLE.starts_with(owned_prefix));
        }
        // Generation-style names are the killswitch's, never the floor.
        assert!(prune_owned("inet", "rustynet_g1"));
        assert!(!is_floor_table("inet", "rustynet_g1"));
        assert!(!is_floor_table("inet", "rustynet_g1_dns"));
        // The floor is one exact identity.
        assert!(is_floor_table("inet", "rustynet_protected_dns"));
        assert!(!is_floor_table("ip", "rustynet_protected_dns"));
        assert!(!is_floor_table("inet", "rustynet_protected_dns_extra"));
    }

    #[test]
    fn violation_labels_are_stable() {
        assert_eq!(FloorViolation::EmptyListing.as_str(), "floor_listing_empty");
        assert_eq!(
            FloorViolation::TruncatedListing.as_str(),
            "floor_listing_truncated"
        );
        assert_eq!(
            FloorViolation::WrongFamily { saw: String::new() }.as_str(),
            "floor_wrong_family"
        );
        assert_eq!(
            FloorViolation::WrongTable { saw: String::new() }.as_str(),
            "floor_wrong_table"
        );
        assert_eq!(FloorViolation::MissingChain.as_str(), "floor_missing_chain");
        assert_eq!(
            FloorViolation::ExtraChain { saw: String::new() }.as_str(),
            "floor_extra_chain"
        );
        assert_eq!(
            FloorViolation::ExtraObject { saw: String::new() }.as_str(),
            "floor_extra_object"
        );
        assert_eq!(
            FloorViolation::WrongHook { saw: String::new() }.as_str(),
            "floor_wrong_hook"
        );
        assert_eq!(
            FloorViolation::WrongPriority { saw: String::new() }.as_str(),
            "floor_wrong_priority"
        );
        assert_eq!(
            FloorViolation::WrongPolicy { saw: String::new() }.as_str(),
            "floor_wrong_policy"
        );
        assert_eq!(
            FloorViolation::MissingRule {
                expected: RULE_UDP_DROP
            }
            .as_str(),
            "floor_missing_rule"
        );
        assert_eq!(
            FloorViolation::ExtraRule { saw: String::new() }.as_str(),
            "floor_extra_rule"
        );
        assert_eq!(FloorViolation::RuleOrder.as_str(), "floor_rule_order");
        assert_eq!(
            FloorViolation::WidenedException { saw: String::new() }.as_str(),
            "floor_exception_widened"
        );
        assert_eq!(
            FloorViolation::ForbiddenExemption { saw: String::new() }.as_str(),
            "floor_forbidden_exemption"
        );
    }
}
