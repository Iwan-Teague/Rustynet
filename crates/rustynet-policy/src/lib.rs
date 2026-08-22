#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficContext {
    Mesh,
    SharedSubnetRouter,
    SharedExit,
    /// Session access to a `serves_nas` host's tunnel-bound storage
    /// API (D13). Service contexts are never matched by rules with
    /// an empty `contexts` list — access requires a rule that names
    /// the context explicitly.
    NasService,
    /// Session access to a `serves_llm` host's tunnel-bound
    /// inference API (D13). Same explicit-naming requirement as
    /// [`TrafficContext::NasService`].
    LlmService,
}

impl TrafficContext {
    /// Whether this is a service-hosting access context
    /// (application-layer session to a nas/llm host) as opposed to
    /// a dataplane traffic context.
    pub fn is_service_context(self) -> bool {
        matches!(
            self,
            TrafficContext::NasService | TrafficContext::LlmService
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub src: String,
    pub dst: String,
    pub protocol: Protocol,
    pub action: RuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub src: String,
    pub dst: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextualAccessRequest {
    pub src: String,
    pub dst: String,
    pub protocol: Protocol,
    pub context: TrafficContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    Active,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct MembershipDirectory {
    nodes: HashMap<String, MembershipStatus>,
    selector_members: HashMap<String, Vec<String>>,
}

impl MembershipDirectory {
    pub fn set_node_status(&mut self, node_id: impl Into<String>, status: MembershipStatus) {
        self.nodes.insert(node_id.into(), status);
    }

    pub fn set_selector_members<I, S>(&mut self, selector: impl Into<String>, node_ids: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.selector_members.insert(
            selector.into(),
            node_ids.into_iter().map(Into::into).collect(),
        );
    }

    pub fn node_status(&self, node_id: &str) -> MembershipStatus {
        self.nodes
            .get(node_id)
            .copied()
            .unwrap_or(MembershipStatus::Unknown)
    }

    /// Returns `true` if at least one node has been registered in this directory.
    ///
    /// # This is NOT a governance-disabled bypass (POL-06)
    ///
    /// The previous doc comment claimed that on an empty directory "the
    /// membership enforcement gate treats nodes as pre-membership and skips the
    /// check so that deployments that have not yet adopted governance are not
    /// broken." **That bypass does not exist and must not be reintroduced.**
    /// `8cca1458` removed it under RN-11 ("empty membership directory denies peer
    /// provisioning") and deleted the twin comment in `phase10.rs`, but left this
    /// one standing as untouched context — so the crate's own documentation
    /// advertised a fail-open that the code had already closed.
    ///
    /// What the code actually does: `selector_membership_allowed` never consults
    /// this method, and an empty directory with a `node:` selector evaluates to
    /// `Deny`. That is the mandated posture — absent trust state denies — and the
    /// test named after this comment pins it.
    ///
    /// Correcting the comment is the point. A stale doc describing a removed
    /// fail-open is an invitation to "restore" it, and this one had already
    /// outlived the code it described by long enough to be cited as current
    /// behaviour in a security review.
    ///
    /// Remaining callers use this as an *advisory* signal about whether
    /// membership state has been distributed yet, never to decide access.
    pub fn is_populated(&self) -> bool {
        !self.nodes.is_empty()
    }

    fn selector_members(&self, selector: &str) -> Option<&[String]> {
        self.selector_members.get(selector).map(Vec::as_slice)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn evaluate(&self, request: &AccessRequest) -> Decision {
        for rule in &self.rules {
            if !selector_matches(&rule.src, &request.src) {
                continue;
            }
            if !selector_matches(&rule.dst, &request.dst) {
                continue;
            }
            if rule.protocol != Protocol::Any && rule.protocol != request.protocol {
                continue;
            }

            return match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny,
            };
        }

        Decision::Deny
    }

    pub fn evaluate_with_membership(
        &self,
        request: &AccessRequest,
        membership: &MembershipDirectory,
    ) -> Decision {
        if !membership_request_allowed(request.src.as_str(), request.dst.as_str(), membership) {
            return Decision::Deny;
        }

        for rule in &self.rules {
            if !membership_rule_allowed(rule.src.as_str(), rule.dst.as_str(), membership) {
                continue;
            }
            if !selector_matches(&rule.src, &request.src) {
                continue;
            }
            if !selector_matches(&rule.dst, &request.dst) {
                continue;
            }
            if rule.protocol != Protocol::Any && rule.protocol != request.protocol {
                continue;
            }

            return match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny,
            };
        }

        Decision::Deny
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextualPolicyRule {
    pub src: String,
    pub dst: String,
    pub protocol: Protocol,
    pub action: RuleAction,
    pub contexts: Vec<TrafficContext>,
}

#[derive(Debug, Clone, Default)]
pub struct ContextualPolicySet {
    pub rules: Vec<ContextualPolicyRule>,
}

impl ContextualPolicySet {
    pub fn evaluate(&self, request: &ContextualAccessRequest) -> Decision {
        for rule in &self.rules {
            if !selector_matches(&rule.src, &request.src) {
                continue;
            }
            if !selector_matches(&rule.dst, &request.dst) {
                continue;
            }
            if rule.protocol != Protocol::Any && rule.protocol != request.protocol {
                continue;
            }
            if !context_matches(&rule.contexts, request.context) {
                continue;
            }

            return match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny,
            };
        }

        Decision::Deny
    }

    pub fn evaluate_with_membership(
        &self,
        request: &ContextualAccessRequest,
        membership: &MembershipDirectory,
    ) -> Decision {
        if !membership_request_allowed(request.src.as_str(), request.dst.as_str(), membership) {
            return Decision::Deny;
        }

        for rule in &self.rules {
            if !membership_rule_allowed(rule.src.as_str(), rule.dst.as_str(), membership) {
                continue;
            }
            if !selector_matches(&rule.src, &request.src) {
                continue;
            }
            if !selector_matches(&rule.dst, &request.dst) {
                continue;
            }
            if rule.protocol != Protocol::Any && rule.protocol != request.protocol {
                continue;
            }
            if !context_matches(&rule.contexts, request.context) {
                continue;
            }

            return match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny,
            };
        }

        Decision::Deny
    }
}

/// Per-peer (or per-group) restriction attached to an existing
/// `LlmService` allow decision. Scopes only ever *narrow* what an
/// authorised peer may do — they are never an authorisation source:
/// the gateway must first obtain `Decision::Allow` from
/// [`ContextualPolicySet::evaluate_with_membership`] for
/// `TrafficContext::LlmService`, then apply the scope. A peer with
/// no scope entry keeps the full grant (the grant itself is the
/// authorisation; scoping is an optional admin restriction).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LlmAccessScope {
    /// Models the peer may invoke. `None` = the grant is
    /// unrestricted (any model the node offers). `Some(list)` =
    /// only the named models; an empty list denies every model.
    pub allowed_models: Option<Vec<String>>,
    /// Token budget per accounting window. `None` = no token quota.
    pub max_tokens_per_window: Option<u64>,
    /// Request-rate ceiling per minute. `None` = no rate ceiling.
    pub max_requests_per_minute: Option<u32>,
}

impl LlmAccessScope {
    /// Whether this scope permits invoking `model`. Purely a
    /// restriction check — callers must already hold an Allow
    /// decision for the peer.
    pub fn permits_model(&self, model: &str) -> bool {
        match &self.allowed_models {
            None => true,
            Some(models) => models.iter().any(|m| m == model),
        }
    }
}

/// Selector → [`LlmAccessScope`] table distributed alongside the
/// signed service-access policy.
///
/// # Specificity is the CALLER's responsibility (POL-12)
///
/// This doc used to claim that "lookup prefers the most specific selector: an
/// exact peer selector (e.g. `node:laptop-1`) wins over a group selector (e.g.
/// `group:family`); first match wins within each specificity tier". There is no
/// tier concept, no prefix parsing and no ranking anywhere in this type —
/// [`LlmScopePolicy::scope_for`] walks the selectors the CALLER supplies, in the
/// order supplied, and returns the first entry that matches one of them.
///
/// The outcome the old comment described does happen, but only because callers
/// pass `["node:<id>", "group:<g>", …]` in that order. Hand it
/// `["group:family", "node:laptop-1"]` and the group scope wins. The obligation
/// is real and it is the caller's; documenting it as a property of this type hid
/// that, and a reader could reasonably have added a caller that ordered
/// selectors differently and silently widened every scope it resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlmScopePolicy {
    pub entries: Vec<(String, LlmAccessScope)>,
}

impl LlmScopePolicy {
    /// Resolve the effective scope for a peer.
    ///
    /// `peer_selectors` MUST be ordered by decreasing specificity — typically
    /// `["node:<id>", "group:<g1>", …]`. This method does not sort, rank or
    /// parse them; it returns the scope for the first supplied selector that has
    /// an entry, so the caller's ordering IS the precedence (POL-12).
    ///
    /// Returns `None` when no entry applies, which leaves the grant
    /// unrestricted. That fail-open direction is deliberate here — a scope is an
    /// optional admin restriction layered on top of an Allow decision the caller
    /// already holds, not the authorization itself — but it is also why the
    /// ordering obligation above matters: a mis-ordered call does not error, it
    /// silently resolves a broader scope.
    pub fn scope_for<'a>(&'a self, peer_selectors: &[String]) -> Option<&'a LlmAccessScope> {
        for selector in peer_selectors {
            if let Some((_, scope)) = self
                .entries
                .iter()
                .find(|(entry_selector, _)| entry_selector == selector)
            {
                return Some(scope);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolloutError {
    UnsafeAllowAll,
    UnknownRevision,
    /// POL-08: a revision id that is already staged. Ids are the rollback
    /// target's only handle, so reusing one silently redefines what rolling back
    /// to it means.
    DuplicateRevision,
    /// POL-09: a rollback target that has never been active. "Rollback" must
    /// return to a known-good state, not activate something never observed.
    RevisionNeverPromoted,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyRolloutController {
    revisions: HashMap<String, ContextualPolicySet>,
    active_revision: Option<String>,
    canary_revision: Option<String>,
    /// Revision ids that have been active at least once. POL-09: `rollback_to`
    /// requires membership here, so a staged-but-never-observed revision cannot
    /// be activated by a method whose name reads as a safety action.
    promoted_revisions: BTreeSet<String>,
}

impl PolicyRolloutController {
    /// Stage a revision as the canary.
    ///
    /// POL-08: a duplicate id is REFUSED rather than overwriting. The id is the
    /// rollback target's only handle, so a bare `insert` meant
    /// `stage("rev-1", tcp)` → promote → `stage("rev-1", udp)` →
    /// `rollback_to("rev-1")` succeeded while silently activating different
    /// content than the operator rolled back to — and re-staging also silently
    /// made that id the canary again. Rollback is the control operators reach for
    /// when something is already wrong; it must not be the step that changes
    /// what they are returning to.
    ///
    /// Refusing is chosen over content-addressing because it keeps operator-named
    /// ids meaningful. Content-addressed revisions would also fix this and remain
    /// a reasonable future change; either way the invariant is that one id names
    /// one policy forever.
    pub fn stage_revision(
        &mut self,
        revision_id: String,
        policy: ContextualPolicySet,
    ) -> Result<(), RolloutError> {
        validate_policy_safety(&policy)?;
        if self.revisions.contains_key(&revision_id) {
            return Err(RolloutError::DuplicateRevision);
        }
        self.revisions.insert(revision_id.clone(), policy);
        self.canary_revision = Some(revision_id);
        Ok(())
    }

    pub fn promote_canary(&mut self) -> Result<(), RolloutError> {
        let Some(canary) = self.canary_revision.clone() else {
            return Err(RolloutError::UnknownRevision);
        };
        self.promoted_revisions.insert(canary.clone());
        self.active_revision = Some(canary);
        self.canary_revision = None;
        Ok(())
    }

    /// Return to a previously-active revision.
    ///
    /// POL-09: the target must have been promoted at least once. The old check
    /// was `contains_key`, so `stage_revision("rev-evil", …)` followed directly
    /// by `rollback_to("rev-evil")` activated it — skipping the runbook's
    /// "promote to canary, observe canary metrics and audit events" steps
    /// entirely, under a method name that reads as a safety action rather than a
    /// deployment.
    ///
    /// `UnknownRevision` and `RevisionNeverPromoted` are kept distinct so an
    /// operator can tell a typo from a revision that exists but was never
    /// observed running.
    pub fn rollback_to(&mut self, revision_id: &str) -> Result<(), RolloutError> {
        if !self.revisions.contains_key(revision_id) {
            return Err(RolloutError::UnknownRevision);
        }
        if !self.promoted_revisions.contains(revision_id) {
            return Err(RolloutError::RevisionNeverPromoted);
        }
        self.active_revision = Some(revision_id.to_owned());
        self.canary_revision = None;
        Ok(())
    }

    pub fn active_revision(&self) -> Option<&str> {
        self.active_revision.as_deref()
    }
}

/// Refuse to stage a policy that allows everything to everything.
///
/// # POL-07 / RSA-0006: the protocol enumeration evaded this
///
/// The check used to require `protocol == Protocol::Any`, so three rules
/// `*`/`*`/`Tcp`, `*`/`*`/`Udp` and `*`/`*`/`Icmp` staged successfully while
/// being operationally equivalent to allow-all. Enumerating the protocol set is
/// not a narrowing, and a guard that can be stepped around by writing the same
/// policy in three lines is not a guard.
///
/// Any `*` → `*` Allow is now refused regardless of protocol. A rule that
/// genuinely needs to be that broad must name a real selector on at least one
/// side, which is the point: the operator has to say who.
///
/// Scope, stated honestly: this checks the `*`/`*` shape only. It does not model
/// coverage — a rule pair that names every selector in the fleet individually is
/// still equivalent to allow-all and still stages. Closing that needs a
/// membership-aware coverage analysis, which this function does not attempt.
fn validate_policy_safety(policy: &ContextualPolicySet) -> Result<(), RolloutError> {
    let contains_allow_all = policy
        .rules
        .iter()
        .any(|rule| rule.src == "*" && rule.dst == "*" && rule.action == RuleAction::Allow);
    if contains_allow_all {
        return Err(RolloutError::UnsafeAllowAll);
    }
    Ok(())
}

fn selector_matches(rule_value: &str, candidate: &str) -> bool {
    // POL-03: an empty selector is absent trust state, not a harmless literal, so
    // it must never match — in either position.
    //
    // Previously `selector_matches("*", "")` was true, so a request carrying an
    // empty identity was admitted by any wildcard rule. An empty *rule* field
    // likewise matched an empty request field. Now an empty candidate matches
    // nothing (evaluation falls through to the terminal `Decision::Deny`) and a
    // rule with an accidentally-empty selector is inert rather than dangerously
    // permissive.
    //
    // Note precisely what this does and does not do: the deny comes from *this*
    // function, not from the membership gate. `selector_membership_allowed` also
    // refuses an empty selector now (see there), but any future evaluator that
    // consults membership without routing through `selector_matches` would need
    // its own guard. No caller in this workspace emits an empty selector, so this
    // cannot false-reject a real request.
    // The `candidate` half is what actually closes the hole. The `rule_value` half
    // is currently REDUNDANT and no test can distinguish it: under equality
    // matching an empty rule value already fails (`"" != "*"` and `"" != <any real
    // identity>`), so the only case it decides is both-empty, which the candidate
    // half already covers. It is kept anyway so the invariant is stated locally
    // rather than depending on the matching semantics below — if this function ever
    // gains prefix or glob matching, an empty pattern could otherwise match
    // everything. Stated explicitly so nobody reads it as tested behaviour.
    if rule_value.is_empty() || candidate.is_empty() {
        return false;
    }
    rule_value == "*" || rule_value == candidate
}

fn context_matches(allowed_contexts: &[TrafficContext], candidate: TrafficContext) -> bool {
    if allowed_contexts.is_empty() {
        // An empty contexts list is the legacy "applies to all
        // dataplane contexts" form. It deliberately does NOT match
        // service-hosting contexts: a pre-D13 rule must never start
        // granting application-layer NAS/LLM access just because the
        // context taxonomy grew. Service access requires a rule that
        // names the service context explicitly (default-deny).
        return !candidate.is_service_context();
    }
    allowed_contexts.contains(&candidate)
}

fn membership_rule_allowed(
    src_selector: &str,
    dst_selector: &str,
    membership: &MembershipDirectory,
) -> bool {
    selector_membership_allowed(src_selector, membership)
        && selector_membership_allowed(dst_selector, membership)
}

fn membership_request_allowed(src: &str, dst: &str, membership: &MembershipDirectory) -> bool {
    selector_membership_allowed(src, membership) && selector_membership_allowed(dst, membership)
}

fn selector_membership_allowed(selector: &str, membership: &MembershipDirectory) -> bool {
    // POL-03: an empty selector is absent trust state — refuse it here too, so the
    // revocation gate does not depend on `selector_matches` having already
    // rejected it. Before POL-01 removed it, `selector_requires_membership("")`
    // returned false here and an empty identity passed the gate unexamined.
    if selector.is_empty() {
        return false;
    }
    // POL-01: an unrecognised selector is unresolvable trust state, not a
    // harmless literal. This match is exhaustive over `SelectorKind` on purpose:
    // adding a variant without deciding its membership semantics fails to
    // compile, so a future selector form cannot silently inherit an allow.
    let Some(kind) = parse_selector(selector) else {
        return false;
    };
    match kind {
        // Matches anything; there is no identity to resolve.
        SelectorKind::Wildcard => return true,
        // A literal network destination carries no membership. See
        // `SelectorKind::Cidr` — an explicitly enumerated allow, not a
        // fallthrough, and unchanged in behaviour from before this fix.
        SelectorKind::Cidr(_) => return true,
        SelectorKind::Node(_)
        | SelectorKind::User(_)
        | SelectorKind::Group(_)
        | SelectorKind::Tag(_) => {}
    }
    let Some(node_id) = selector_node_id(selector) else {
        let Some(members) = membership.selector_members(selector) else {
            return false;
        };
        return !members.is_empty()
            && members
                .iter()
                .all(|node_id| membership.node_status(node_id) == MembershipStatus::Active);
    };
    membership.node_status(node_id) == MembershipStatus::Active
}

fn selector_node_id(selector: &str) -> Option<&str> {
    match parse_selector(selector) {
        Some(SelectorKind::Node(id)) => Some(id),
        _ => None,
    }
}

/// Every selector form this engine recognises.
///
/// POL-01: the point of this enum is that the set is CLOSED. The previous design
/// asked "does this selector start with a known prefix?" and, on a miss, returned
/// `false` from the former `selector_requires_membership` helper — which
/// `selector_membership_allowed` read as "not an identity, therefore nothing to
/// check" and allowed. So an unrecognised string was reclassified as harmless
/// rather than as unresolvable trust state, and the revocation check never ran.
///
/// Confirmed consequences of that inversion, against the daemon's own shipped
/// default policy with `revoked-node` marked `Revoked`: `node:revoked-node` was
/// correctly denied, while `NODE:revoked-node`, `Node:revoked-node`,
/// `nodes:revoked-node`, `svc:revoked-node`, `" node:revoked-node"` (leading
/// space) and the bare `revoked-node` were all ALLOWED.
///
/// Now every selector must parse into one of these variants and anything else
/// denies. Each variant that permits without a membership lookup does so
/// EXPLICITLY, so the allow is enumerated rather than reached by fallthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectorKind<'a> {
    /// `*` — matches anything. No identity to resolve.
    Wildcard,
    /// `node:<id>` — resolves to a single membership entry.
    Node(&'a str),
    /// `user:<name>` — resolves via the directory's selector members.
    User(&'a str),
    /// `group:<name>`.
    Group(&'a str),
    /// `tag:<name>`.
    Tag(&'a str),
    /// A literal network destination such as `192.168.1.0/24` or `100.64.0.2/32`.
    ///
    /// Not an identity, so no membership lookup applies — but it is a real and
    /// load-bearing selector form: LAN-route grants and exit-route intents pass
    /// `route.destination_cidr` / `request.cidr` straight through as `dst`.
    /// Recognising it explicitly is what lets the miss branch deny without
    /// breaking route authorization. Whether a literal CIDR *should* be
    /// authorizable without resolving a peer is a separate open question
    /// (POL-02); this change does not alter that behaviour, only stops it sharing
    /// a code path with an unrecognised string.
    Cidr(&'a str),
}

/// Parse a selector into its kind, or `None` if it conforms to no known form.
///
/// Deliberately strict, and deliberately NOT canonicalising:
///
/// - **Case-sensitive.** `NODE:x` is rejected rather than folded to `node:x`.
///   Folding would make a mis-cased selector start MATCHING, which widens what a
///   rule admits; rejecting keeps the failure direction closed.
/// - **No trimming.** `" node:x"` is rejected rather than trimmed. Trimming is
///   also a widening: it makes two distinct strings match.
/// - **A prefix with an empty body is malformed**, so `node:` cannot reach a
///   membership lookup with an empty id.
///
/// Note: this REPLACES the former `selector_requires_membership` helper rather
/// than sitting alongside it. That helper's whole contract was "false means no
/// membership check applies", which is the fail-open shape POL-01 is about, so
/// keeping it available would leave the defect one call site away from returning.
fn parse_selector(selector: &str) -> Option<SelectorKind<'_>> {
    if selector == "*" {
        return Some(SelectorKind::Wildcard);
    }
    if selector.is_empty() {
        return None;
    }
    if let Some(body) = selector.strip_prefix("node:") {
        return (!body.is_empty()).then_some(SelectorKind::Node(body));
    }
    if let Some(body) = selector.strip_prefix("user:") {
        return (!body.is_empty()).then_some(SelectorKind::User(body));
    }
    if let Some(body) = selector.strip_prefix("group:") {
        return (!body.is_empty()).then_some(SelectorKind::Group(body));
    }
    if let Some(body) = selector.strip_prefix("tag:") {
        return (!body.is_empty()).then_some(SelectorKind::Tag(body));
    }
    if selector_is_literal_cidr(selector) {
        return Some(SelectorKind::Cidr(selector));
    }
    None
}

/// Whether a selector is a syntactically valid literal CIDR.
///
/// Validated rather than sniffed for a `/`: "contains a slash" would simply move
/// the fail-open miss branch behind a cheaper test, which is the defect this
/// change exists to remove. The address must parse and the prefix length must be
/// in range for its family.
fn selector_is_literal_cidr(selector: &str) -> bool {
    let Some((address, prefix)) = selector.split_once('/') else {
        return false;
    };
    // Reject a redundantly-written prefix such as `/024`, so one network has one
    // spelling and any allowlist keyed on the text cannot be bypassed by
    // rewriting it.
    if prefix.len() > 1 && prefix.starts_with('0') {
        return false;
    }
    let Ok(prefix_len) = prefix.parse::<u8>() else {
        return false;
    };
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => prefix_len <= 32,
        Ok(std::net::IpAddr::V6(_)) => prefix_len <= 128,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccessRequest, ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet,
        Decision, LlmAccessScope, LlmScopePolicy, MembershipDirectory, MembershipStatus,
        PolicyRolloutController, PolicyRule, PolicySet, Protocol, RolloutError, RuleAction,
        TrafficContext, selector_membership_allowed,
    };

    /// POL-01, verbatim from the review's confirmed exploit table.
    ///
    /// Each of these was ALLOWED against the daemon's shipped default policy with
    /// `revoked-node` marked `Revoked`, because the former
    /// `selector_requires_membership` helper returned false on a prefix miss and
    /// the caller read that as "nothing to check". Every one must now be denied.
    #[test]
    fn unrecognised_selectors_do_not_skip_the_revocation_check() {
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("revoked-node", MembershipStatus::Revoked);
        membership.set_node_status("active-node", MembershipStatus::Active);

        // The control: the correctly-spelled selector was already denied.
        assert!(
            !selector_membership_allowed("node:revoked-node", &membership),
            "the correctly-spelled revoked selector must deny"
        );

        for evasion in [
            // Case variants -- rejected rather than folded, since folding would
            // make a mis-cased selector start matching.
            "NODE:revoked-node",
            "Node:revoked-node",
            "nOdE:revoked-node",
            // Near-miss prefixes.
            "nodes:revoked-node",
            "svc:revoked-node",
            "node-revoked-node",
            "node.revoked-node",
            // Whitespace -- rejected rather than trimmed.
            " node:revoked-node",
            "node:revoked-node ",
            "\tnode:revoked-node",
            // No prefix at all: a bare id is not a selector.
            "revoked-node",
            // A prefix with no body cannot reach a membership lookup.
            "node:",
            "user:",
            "group:",
            "tag:",
            // Not a valid CIDR, so it must not be classified as one. Sniffing for
            // a `/` would simply relocate the fail-open branch.
            "node/revoked",
            "999.999.999.999/24",
            "192.168.1.0/33",
            "192.168.1.0/",
            "192.168.1.0/24extra",
            "::1/129",
            // A redundantly-written prefix: one network, one spelling.
            "192.168.1.0/024",
        ] {
            assert!(
                !selector_membership_allowed(evasion, &membership),
                "an unrecognised selector must deny, not skip the revocation check: {evasion:?}"
            );
        }
    }

    /// The other direction: every selector form this workspace actually emits
    /// must still resolve, or the strict parser breaks real authorization.
    ///
    /// The literal-CIDR form is the one that makes this non-obvious. LAN-route
    /// grants and exit-route intents pass `route.destination_cidr` /
    /// `request.cidr` through as `dst`, so denying unrecognised selectors without
    /// recognising a CIDR would have failed route authorization closed.
    #[test]
    fn every_selector_form_in_use_still_resolves() {
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("active-node", MembershipStatus::Active);
        membership.set_selector_members("user:local", vec!["active-node".to_owned()]);
        membership.set_selector_members("group:family", vec!["active-node".to_owned()]);
        membership.set_selector_members("tag:servers", vec!["active-node".to_owned()]);

        for allowed in [
            "*",
            "node:active-node",
            "user:local",
            "group:family",
            "tag:servers",
            // Literal destinations, as emitted by the route paths.
            "192.168.1.0/24",
            "100.64.0.2/32",
            "0.0.0.0/0",
            "10.0.0.0/8",
            "fd00::/8",
            "::1/128",
        ] {
            assert!(
                selector_membership_allowed(allowed, &membership),
                "a selector form this workspace emits must still resolve: {allowed:?}"
            );
        }
    }

    /// POL-06: an empty membership directory DENIES; `is_populated()` is not a
    /// bypass. This is the behaviour the corrected doc comment on
    /// `MembershipDirectory::is_populated` describes, pinned so the removed
    /// fail-open cannot come back with the comment that used to advertise it.
    #[test]
    fn an_empty_membership_directory_denies_rather_than_skipping_the_check() {
        let membership = MembershipDirectory::default();
        assert!(
            !membership.is_populated(),
            "the directory under test must be empty"
        );
        for selector in ["node:any-node", "user:local", "group:family", "tag:servers"] {
            assert!(
                !selector_membership_allowed(selector, &membership),
                "an empty directory must deny {selector:?}, not treat it as pre-membership"
            );
        }
        // The wildcard resolves no identity, so it is unaffected either way --
        // stated so the assertion above is not misread as "everything denies".
        assert!(selector_membership_allowed("*", &membership));
    }

    fn allow_all_rule(protocol: Protocol) -> ContextualPolicyRule {
        ContextualPolicyRule {
            src: "*".to_owned(),
            dst: "*".to_owned(),
            protocol,
            action: RuleAction::Allow,
            contexts: vec![TrafficContext::Mesh],
        }
    }

    /// POL-07 / RSA-0006: enumerating protocols was equivalent to allow-all and
    /// staged successfully, because the guard required `Protocol::Any`.
    #[test]
    fn protocol_enumeration_no_longer_evades_the_allow_all_guard() {
        for protocol in [Protocol::Any, Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let mut controller = PolicyRolloutController::default();
            let policy = ContextualPolicySet {
                rules: vec![allow_all_rule(protocol)],
            };
            assert_eq!(
                controller.stage_revision("rev-1".to_owned(), policy),
                Err(RolloutError::UnsafeAllowAll),
                "a `*` -> `*` Allow must be refused for protocol {protocol:?}"
            );
        }

        // The original reported evasion: the three specific protocols together.
        let mut controller = PolicyRolloutController::default();
        let enumerated = ContextualPolicySet {
            rules: vec![
                allow_all_rule(Protocol::Tcp),
                allow_all_rule(Protocol::Udp),
                allow_all_rule(Protocol::Icmp),
            ],
        };
        assert_eq!(
            controller.stage_revision("rev-enum".to_owned(), enumerated),
            Err(RolloutError::UnsafeAllowAll)
        );
    }

    /// A rule that names a real selector on either side must still stage, or the
    /// guard blocks every usable policy.
    #[test]
    fn a_policy_naming_a_real_selector_still_stages() {
        let mut controller = PolicyRolloutController::default();
        let policy = ContextualPolicySet {
            rules: vec![
                ContextualPolicyRule {
                    src: "user:local".to_owned(),
                    dst: "*".to_owned(),
                    protocol: Protocol::Any,
                    action: RuleAction::Allow,
                    contexts: vec![TrafficContext::Mesh],
                },
                // A `*` -> `*` DENY is a tightening, not an allow-all.
                ContextualPolicyRule {
                    src: "*".to_owned(),
                    dst: "*".to_owned(),
                    protocol: Protocol::Any,
                    action: RuleAction::Deny,
                    contexts: vec![TrafficContext::Mesh],
                },
            ],
        };
        controller
            .stage_revision("rev-1".to_owned(), policy)
            .expect("a policy naming a real selector must stage");
    }

    fn narrow_policy(protocol: Protocol) -> ContextualPolicySet {
        ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_owned(),
                dst: "node:target".to_owned(),
                protocol,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        }
    }

    /// POL-08: re-staging an id silently redefined what rolling back to it meant.
    ///
    /// The confirmed sequence was stage `rev-1` (Tcp) -> promote -> re-stage
    /// `rev-1` (Udp) -> `rollback_to("rev-1")` -> Ok, with the content replaced.
    #[test]
    fn a_duplicate_revision_id_is_refused_rather_than_overwriting() {
        let mut controller = PolicyRolloutController::default();
        controller
            .stage_revision("rev-1".to_owned(), narrow_policy(Protocol::Tcp))
            .expect("first stage should succeed");
        controller.promote_canary().expect("promote should succeed");

        assert_eq!(
            controller.stage_revision("rev-1".to_owned(), narrow_policy(Protocol::Udp)),
            Err(RolloutError::DuplicateRevision),
            "one id must name one policy forever"
        );
        // And the refusal must not have disturbed the active revision or made the
        // re-staged id the canary again.
        assert_eq!(controller.active_revision(), Some("rev-1"));
        controller
            .rollback_to("rev-1")
            .expect("the original revision must still be the rollback target");
    }

    /// POL-09: `rollback_to` activated never-promoted revisions, skipping the
    /// runbook's canary-observation steps under a method name that reads as a
    /// safety action.
    #[test]
    fn rollback_refuses_a_revision_that_was_never_promoted() {
        let mut controller = PolicyRolloutController::default();
        controller
            .stage_revision("rev-evil".to_owned(), narrow_policy(Protocol::Tcp))
            .expect("stage should succeed");

        assert_eq!(
            controller.rollback_to("rev-evil"),
            Err(RolloutError::RevisionNeverPromoted),
            "a staged-but-never-observed revision must not be activatable via rollback"
        );
        assert_eq!(controller.active_revision(), None);

        // A typo stays distinguishable from a never-promoted revision.
        assert_eq!(
            controller.rollback_to("rev-typo"),
            Err(RolloutError::UnknownRevision)
        );

        // Once actually promoted, rollback to it works -- so this is a gate on
        // provenance, not a block on the feature.
        controller.promote_canary().expect("promote should succeed");
        controller
            .stage_revision("rev-2".to_owned(), narrow_policy(Protocol::Udp))
            .expect("stage should succeed");
        controller.promote_canary().expect("promote should succeed");
        assert_eq!(controller.active_revision(), Some("rev-2"));
        controller
            .rollback_to("rev-evil")
            .expect("a previously-promoted revision is a valid rollback target");
        assert_eq!(controller.active_revision(), Some("rev-evil"));
    }

    /// POL-12: `scope_for` has no specificity logic — the CALLER's selector order
    /// is the precedence. The pre-existing test passes because it happens to pass
    /// node-first, which reads as proof of tiering the code does not have.
    #[test]
    fn scope_for_precedence_comes_from_the_caller_order_not_from_specificity() {
        let node_scope = LlmAccessScope {
            allowed_models: Some(vec!["small-model".to_owned()]),
            ..LlmAccessScope::default()
        };
        let group_scope = LlmAccessScope {
            allowed_models: Some(vec!["small-model".to_owned(), "big-model".to_owned()]),
            ..LlmAccessScope::default()
        };
        let policy = LlmScopePolicy {
            entries: vec![
                ("group:family".to_owned(), group_scope.clone()),
                ("node:laptop-1".to_owned(), node_scope.clone()),
            ],
        };

        // Node-first: the narrow scope wins.
        assert_eq!(
            policy.scope_for(&["node:laptop-1".to_owned(), "group:family".to_owned()]),
            Some(&node_scope)
        );
        // Group-first, SAME table: the broad scope wins. If any tiering existed
        // this would still resolve the node scope. It does not, which is exactly
        // what the corrected doc comment now says.
        assert_eq!(
            policy.scope_for(&["group:family".to_owned(), "node:laptop-1".to_owned()]),
            Some(&group_scope),
            "a mis-ordered call silently resolves the BROADER scope -- the ordering \
             obligation is the caller's and is documented as such"
        );
    }

    #[test]
    fn policy_defaults_to_deny() {
        let set = PolicySet::default();
        let request = AccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
        };

        assert_eq!(set.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn empty_policy_set_denies_every_request_shape() {
        // Core default-deny invariant, broader than
        // `policy_defaults_to_deny`: an EMPTY set denies EVERY
        // request shape — every protocol, both policy engines, and
        // even requests from fully-active membership. No rule means
        // no allow, ever.
        let empty = PolicySet::default();
        let empty_contextual = ContextualPolicySet::default();
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-a", MembershipStatus::Active);
        membership.set_node_status("node-b", MembershipStatus::Active);

        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Any] {
            let request = AccessRequest {
                src: "node:a".to_owned(),
                dst: "node:b".to_owned(),
                protocol,
            };
            assert_eq!(
                empty.evaluate(&request),
                Decision::Deny,
                "empty set must deny plain request ({protocol:?})"
            );
            assert_eq!(
                empty.evaluate_with_membership(&request, &membership),
                Decision::Deny,
                "empty set must deny active-membership request ({protocol:?})"
            );

            for context in [
                TrafficContext::Mesh,
                TrafficContext::SharedExit,
                TrafficContext::NasService,
            ] {
                let contextual = ContextualAccessRequest {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol,
                    context,
                };
                assert_eq!(
                    empty_contextual.evaluate(&contextual),
                    Decision::Deny,
                    "empty contextual set must deny ({protocol:?}, {context:?})"
                );
                assert_eq!(
                    empty_contextual.evaluate_with_membership(&contextual, &membership),
                    Decision::Deny,
                    "empty contextual set must deny with active membership \
                     ({protocol:?}, {context:?})"
                );
            }
        }
    }

    #[test]
    fn policy_respects_first_match() {
        let set = PolicySet {
            rules: vec![
                PolicyRule {
                    src: "group:family".to_owned(),
                    dst: "tag:servers".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                },
                PolicyRule {
                    src: "*".to_owned(),
                    dst: "*".to_owned(),
                    protocol: Protocol::Any,
                    action: RuleAction::Deny,
                },
            ],
        };

        let request = AccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
        };

        assert_eq!(set.evaluate(&request), Decision::Allow);
    }

    #[test]
    fn nonempty_policy_set_denies_request_matching_no_rule() {
        // Default-deny holds WITH rules present: every rule here is
        // an ALLOW, and none of them matches this request (wrong src,
        // wrong dst, wrong protocol) — so evaluation falls through
        // every rule and must still terminate in Deny.
        let set = PolicySet {
            rules: vec![
                PolicyRule {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                },
                PolicyRule {
                    src: "group:x".to_owned(),
                    dst: "tag:y".to_owned(),
                    protocol: Protocol::Udp,
                    action: RuleAction::Allow,
                },
            ],
        };
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-a", MembershipStatus::Active);
        membership.set_node_status("node-c", MembershipStatus::Active);

        let off_src = AccessRequest {
            src: "node:c".to_owned(),
            dst: "node:b".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(set.evaluate(&off_src), Decision::Deny);
        assert_eq!(
            set.evaluate_with_membership(&off_src, &membership),
            Decision::Deny
        );

        let off_dst = AccessRequest {
            src: "node:a".to_owned(),
            dst: "node:z".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(set.evaluate(&off_dst), Decision::Deny);

        let off_protocol = AccessRequest {
            src: "node:a".to_owned(),
            dst: "node:b".to_owned(),
            protocol: Protocol::Udp,
        };
        assert_eq!(set.evaluate(&off_protocol), Decision::Deny);
    }

    #[test]
    fn deny_rule_wins_when_it_matches_first() {
        // First-match semantics are fail-safe only because a DENY
        // rule that matches the tuple terminates evaluation before
        // any later ALLOW for the SAME tuple can be reached. Both
        // engines must honour that ordering.
        let set = PolicySet {
            rules: vec![
                PolicyRule {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Deny,
                },
                PolicyRule {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                },
            ],
        };
        let request = AccessRequest {
            src: "node:a".to_owned(),
            dst: "node:b".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(set.evaluate(&request), Decision::Deny);
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-a", MembershipStatus::Active);
        membership.set_node_status("node-b", MembershipStatus::Active);
        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Deny
        );

        let contextual_set = ContextualPolicySet {
            rules: vec![
                ContextualPolicyRule {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Deny,
                    contexts: vec![TrafficContext::Mesh],
                },
                ContextualPolicyRule {
                    src: "node:a".to_owned(),
                    dst: "node:b".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                    contexts: vec![TrafficContext::Mesh],
                },
            ],
        };
        let contextual_request = ContextualAccessRequest {
            src: "node:a".to_owned(),
            dst: "node:b".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::Mesh,
        };
        assert_eq!(contextual_set.evaluate(&contextual_request), Decision::Deny);
    }

    #[test]
    fn absent_or_unknown_tag_requests_are_denied_even_against_wildcard() {
        // POL-03, evaluator level: an EMPTY identity in either
        // position is absent trust state and matches NOTHING — not
        // even a wildcard ALLOW rule. An unknown tag simply matches
        // no rule. Both must fall through to terminal Deny.
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node:a", MembershipStatus::Active);
        membership.set_node_status("tag:servers", MembershipStatus::Active);

        let empty_src = AccessRequest {
            src: String::new(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(set.evaluate(&empty_src), Decision::Deny);
        assert_eq!(
            set.evaluate_with_membership(&empty_src, &membership),
            Decision::Deny
        );

        let empty_dst = AccessRequest {
            src: "node:a".to_owned(),
            dst: String::new(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(set.evaluate(&empty_dst), Decision::Deny);

        // A malformed empty-body tag ("tag:") is NOT the empty-string
        // case: the raw engine's equality matching lets a wildcard
        // match it, and rejecting malformed selector FORMS is the
        // membership gate's job — so pin the denial there.
        let empty_body_tag = AccessRequest {
            src: "node:a".to_owned(),
            dst: "tag:".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(
            set.evaluate_with_membership(&empty_body_tag, &membership),
            Decision::Deny,
            "the membership gate must reject the malformed 'tag:' form"
        );

        let unknown_tag = AccessRequest {
            src: "node:a".to_owned(),
            dst: "tag:never-provisioned".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(
            set.evaluate_with_membership(&unknown_tag, &membership),
            Decision::Deny
        );
    }

    #[test]
    fn single_tag_allow_admits_matching_tag_and_denies_others() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "tag:web".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };

        let web_request = AccessRequest {
            src: "node:a".to_owned(),
            dst: "tag:web".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(
            set.evaluate(&web_request),
            Decision::Allow,
            "a request tagged 'web' must be allowed by the tag rule"
        );

        let db_request = AccessRequest {
            src: "node:a".to_owned(),
            dst: "tag:db".to_owned(),
            protocol: Protocol::Tcp,
        };
        assert_eq!(
            set.evaluate(&db_request),
            Decision::Deny,
            "a request tagged 'db' matches no allow rule and must be denied"
        );
    }

    #[test]
    fn contextual_policy_defaults_to_deny_in_shared_contexts() {
        let set = ContextualPolicySet::default();
        let request = ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        };
        assert_eq!(set.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn protocol_filter_is_preserved_for_shared_exit_context() {
        let set = ContextualPolicySet {
            rules: vec![
                ContextualPolicyRule {
                    src: "group:family".to_owned(),
                    dst: "tag:servers".to_owned(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                    contexts: vec![TrafficContext::SharedExit],
                },
                ContextualPolicyRule {
                    src: "*".to_owned(),
                    dst: "*".to_owned(),
                    protocol: Protocol::Any,
                    action: RuleAction::Deny,
                    contexts: vec![
                        TrafficContext::Mesh,
                        TrafficContext::SharedSubnetRouter,
                        TrafficContext::SharedExit,
                    ],
                },
            ],
        };

        let tcp_request = ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        };
        let udp_request = ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Udp,
            context: TrafficContext::SharedExit,
        };

        assert_eq!(set.evaluate(&tcp_request), Decision::Allow);
        assert_eq!(set.evaluate(&udp_request), Decision::Deny);
    }

    #[test]
    fn contextual_policy_does_not_widen_between_shared_router_and_exit() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_owned(),
                dst: "tag:servers".to_owned(),
                protocol: Protocol::Icmp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedSubnetRouter],
            }],
        };

        let router_request = ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Icmp,
            context: TrafficContext::SharedSubnetRouter,
        };
        let exit_request = ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Icmp,
            context: TrafficContext::SharedExit,
        };

        assert_eq!(set.evaluate(&router_request), Decision::Allow);
        assert_eq!(set.evaluate(&exit_request), Decision::Deny);
    }

    #[test]
    fn rollout_controller_rejects_allow_all_and_supports_rollback() {
        let mut controller = PolicyRolloutController::default();

        let invalid_policy = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![
                    TrafficContext::Mesh,
                    TrafficContext::SharedSubnetRouter,
                    TrafficContext::SharedExit,
                ],
            }],
        };
        let rejected_result = controller.stage_revision("rev-blocked".to_owned(), invalid_policy);
        assert_eq!(rejected_result.err(), Some(RolloutError::UnsafeAllowAll));

        let safe_policy_v1 = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_owned(),
                dst: "tag:servers".to_owned(),
                protocol: Protocol::Tcp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        controller
            .stage_revision("rev-1".to_owned(), safe_policy_v1)
            .expect("safe revision should stage");
        controller.promote_canary().expect("canary should promote");
        assert_eq!(controller.active_revision(), Some("rev-1"));

        let safe_policy_v2 = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_owned(),
                dst: "tag:servers".to_owned(),
                protocol: Protocol::Udp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        controller
            .stage_revision("rev-2".to_owned(), safe_policy_v2)
            .expect("second safe revision should stage");
        controller.promote_canary().expect("canary should promote");
        assert_eq!(controller.active_revision(), Some("rev-2"));

        controller
            .rollback_to("rev-1")
            .expect("rollback should target known revision");
        assert_eq!(controller.active_revision(), Some("rev-1"));
    }

    #[test]
    fn membership_aware_contextual_policy_denies_revoked_and_unknown_nodes() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_owned(),
                dst: "node:node-exit".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedExit],
            }],
        };

        let request = ContextualAccessRequest {
            src: "user:local".to_owned(),
            dst: "node:node-exit".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        };

        let unknown_membership = MembershipDirectory::default();
        assert_eq!(
            set.evaluate_with_membership(&request, &unknown_membership),
            Decision::Deny
        );

        let mut revoked_membership = MembershipDirectory::default();
        revoked_membership.set_node_status("local-operator", MembershipStatus::Active);
        revoked_membership.set_node_status("node-exit", MembershipStatus::Revoked);
        revoked_membership.set_selector_members("user:local", ["local-operator"]);
        assert_eq!(
            set.evaluate_with_membership(&request, &revoked_membership),
            Decision::Deny
        );

        let mut active_membership = MembershipDirectory::default();
        active_membership.set_node_status("local-operator", MembershipStatus::Active);
        active_membership.set_node_status("node-exit", MembershipStatus::Active);
        active_membership.set_selector_members("user:local", ["local-operator"]);
        assert_eq!(
            set.evaluate_with_membership(&request, &active_membership),
            Decision::Allow
        );
    }

    #[test]
    fn membership_aware_policy_preserves_protocol_filters() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_owned(),
                dst: "node:node-a".to_owned(),
                protocol: Protocol::Tcp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("local-operator", MembershipStatus::Active);
        membership.set_node_status("node-a", MembershipStatus::Active);
        membership.set_selector_members("user:local", ["local-operator"]);

        let tcp = ContextualAccessRequest {
            src: "user:local".to_owned(),
            dst: "node:node-a".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::Mesh,
        };
        let udp = ContextualAccessRequest {
            src: "user:local".to_owned(),
            dst: "node:node-a".to_owned(),
            protocol: Protocol::Udp,
            context: TrafficContext::Mesh,
        };

        assert_eq!(
            set.evaluate_with_membership(&tcp, &membership),
            Decision::Allow
        );
        assert_eq!(
            set.evaluate_with_membership(&udp, &membership),
            Decision::Deny
        );
    }

    #[test]
    fn membership_aware_policy_denies_node_selectors_when_directory_empty() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "node:node-a".to_owned(),
                dst: "node:node-b".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let request = AccessRequest {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Tcp,
        };
        let membership = MembershipDirectory::default();

        assert!(!membership.is_populated());
        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Deny
        );
    }

    #[test]
    fn wildcard_rule_does_not_bypass_revoked_node_request_membership() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let request = AccessRequest {
            src: "node:revoked-node".to_owned(),
            dst: "node:active-node".to_owned(),
            protocol: Protocol::Tcp,
        };
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("revoked-node", MembershipStatus::Revoked);
        membership.set_node_status("active-node", MembershipStatus::Active);

        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Deny
        );
    }

    #[test]
    fn non_node_selectors_require_membership_resolution() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "group:family".to_owned(),
                dst: "tag:servers".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let request = AccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
        };

        let mut unresolved = MembershipDirectory::default();
        unresolved.set_node_status("node-a", MembershipStatus::Active);
        unresolved.set_node_status("node-server", MembershipStatus::Active);
        assert_eq!(
            set.evaluate_with_membership(&request, &unresolved),
            Decision::Deny,
            "unmapped non-node selectors must fail closed"
        );

        let mut with_revoked_member = MembershipDirectory::default();
        with_revoked_member.set_node_status("node-a", MembershipStatus::Revoked);
        with_revoked_member.set_node_status("node-server", MembershipStatus::Active);
        with_revoked_member.set_selector_members("group:family", ["node-a"]);
        with_revoked_member.set_selector_members("tag:servers", ["node-server"]);
        assert_eq!(
            set.evaluate_with_membership(&request, &with_revoked_member),
            Decision::Deny,
            "revoked selector member must deny the grouped allow rule"
        );

        let mut active = MembershipDirectory::default();
        active.set_node_status("node-a", MembershipStatus::Active);
        active.set_node_status("node-server", MembershipStatus::Active);
        active.set_selector_members("group:family", ["node-a"]);
        active.set_selector_members("tag:servers", ["node-server"]);
        assert_eq!(
            set.evaluate_with_membership(&request, &active),
            Decision::Allow
        );
    }

    #[test]
    fn literal_route_destinations_do_not_require_membership_resolution() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        let request = ContextualAccessRequest {
            src: "user:local".to_owned(),
            dst: "100.64.0.2/32".to_owned(),
            protocol: Protocol::Any,
            context: TrafficContext::Mesh,
        };
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("local-operator", MembershipStatus::Active);
        membership.set_selector_members("user:local", ["local-operator"]);

        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Allow
        );
    }

    /// M5: A revoked node's traffic must be denied even when a permissive ACL
    /// rule would otherwise allow it (revocation check runs before rule eval).
    #[test]
    fn test_revoked_node_acl_denied_before_rule_evaluation() {
        // Wildcard allow-all rule — most permissive possible
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "*".to_owned(),
                dst: "node:revoked-node".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        let request = ContextualAccessRequest {
            src: "user:alice".to_owned(),
            dst: "node:revoked-node".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::Mesh,
        };

        let mut membership = MembershipDirectory::default();
        membership.set_node_status("revoked-node", MembershipStatus::Revoked);

        // Must deny despite the permissive rule
        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Deny,
            "revoked node must be denied even with a permissive allow rule"
        );
    }

    /// D13.b E2: an empty policy set denies service-context access
    /// (the engine's `Decision::Deny` default covers the service
    /// contexts exactly like the dataplane contexts).
    #[test]
    fn service_contexts_default_to_deny_on_empty_policy() {
        let set = ContextualPolicySet::default();
        for context in [TrafficContext::NasService, TrafficContext::LlmService] {
            let request = ContextualAccessRequest {
                src: "node:laptop-1".to_owned(),
                dst: "node:service-host".to_owned(),
                protocol: Protocol::Tcp,
                context,
            };
            assert_eq!(
                set.evaluate(&request),
                Decision::Deny,
                "empty policy must deny {context:?}"
            );
        }
    }

    /// D13.b E2: an explicit (peer → NasService) allow grants exactly
    /// that peer and exactly that service — a different peer stays
    /// denied, and the same peer stays denied for `LlmService`
    /// (no cross-service widening).
    #[test]
    fn service_allow_is_scoped_to_peer_and_service() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "node:laptop-1".to_owned(),
                dst: "node:nas-host".to_owned(),
                protocol: Protocol::Tcp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::NasService],
            }],
        };

        let allowed_peer = ContextualAccessRequest {
            src: "node:laptop-1".to_owned(),
            dst: "node:nas-host".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::NasService,
        };
        let other_peer = ContextualAccessRequest {
            src: "node:laptop-2".to_owned(),
            ..allowed_peer.clone()
        };
        let other_service = ContextualAccessRequest {
            context: TrafficContext::LlmService,
            ..allowed_peer.clone()
        };

        assert_eq!(set.evaluate(&allowed_peer), Decision::Allow);
        assert_eq!(
            set.evaluate(&other_peer),
            Decision::Deny,
            "allow for laptop-1 must not leak to laptop-2"
        );
        assert_eq!(
            set.evaluate(&other_service),
            Decision::Deny,
            "NasService allow must not widen to LlmService"
        );
    }

    /// D13.b hazard pin: a rule with an EMPTY `contexts` list is the
    /// legacy "all dataplane contexts" form. It matches
    /// Mesh/SharedSubnetRouter/SharedExit but deliberately does NOT
    /// match the service contexts — a pre-D13 wildcard-context rule
    /// must never silently start granting NAS/LLM application access
    /// (see `context_matches`).
    #[test]
    fn empty_contexts_rule_matches_dataplane_but_never_service_contexts() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_owned(),
                dst: "tag:servers".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![],
            }],
        };

        let request_in = |context| ContextualAccessRequest {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Tcp,
            context,
        };

        for dataplane_context in [
            TrafficContext::Mesh,
            TrafficContext::SharedSubnetRouter,
            TrafficContext::SharedExit,
        ] {
            assert_eq!(
                set.evaluate(&request_in(dataplane_context)),
                Decision::Allow,
                "legacy empty-contexts rule must keep matching {dataplane_context:?}"
            );
        }
        for service_context in [TrafficContext::NasService, TrafficContext::LlmService] {
            assert_eq!(
                set.evaluate(&request_in(service_context)),
                Decision::Deny,
                "legacy empty-contexts rule must never match {service_context:?}"
            );
        }
    }

    /// D13.b E2: the membership gate runs for service contexts too —
    /// a revoked or unknown `node:*` selector is denied even when a
    /// permissive allow rule names the service context.
    #[test]
    fn service_context_membership_gate_denies_revoked_and_unknown_peers() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "*".to_owned(),
                dst: "node:nas-host".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::NasService],
            }],
        };
        let request = ContextualAccessRequest {
            src: "node:peer-1".to_owned(),
            dst: "node:nas-host".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::NasService,
        };

        let mut revoked_membership = MembershipDirectory::default();
        revoked_membership.set_node_status("peer-1", MembershipStatus::Revoked);
        revoked_membership.set_node_status("nas-host", MembershipStatus::Active);
        assert_eq!(
            set.evaluate_with_membership(&request, &revoked_membership),
            Decision::Deny,
            "revoked peer must be denied service access despite the allow rule"
        );

        let mut unknown_membership = MembershipDirectory::default();
        unknown_membership.set_node_status("nas-host", MembershipStatus::Active);
        assert_eq!(
            set.evaluate_with_membership(&request, &unknown_membership),
            Decision::Deny,
            "unknown peer must be denied service access despite the allow rule"
        );

        let mut active_membership = MembershipDirectory::default();
        active_membership.set_node_status("peer-1", MembershipStatus::Active);
        active_membership.set_node_status("nas-host", MembershipStatus::Active);
        assert_eq!(
            set.evaluate_with_membership(&request, &active_membership),
            Decision::Allow,
            "active peer proceeds to rule evaluation"
        );
    }

    #[test]
    fn is_service_context_truth_table() {
        assert!(!TrafficContext::Mesh.is_service_context());
        assert!(!TrafficContext::SharedSubnetRouter.is_service_context());
        assert!(!TrafficContext::SharedExit.is_service_context());
        assert!(TrafficContext::NasService.is_service_context());
        assert!(TrafficContext::LlmService.is_service_context());
    }

    /// D13.b: scope model-restriction truth table — `None` permits
    /// any model, `Some(list)` permits only the listed models, and
    /// `Some(empty)` permits none.
    #[test]
    fn llm_access_scope_permits_model_truth_table() {
        let unrestricted = LlmAccessScope::default();
        assert!(unrestricted.allowed_models.is_none());
        assert!(unrestricted.permits_model("any-model"));

        let listed = LlmAccessScope {
            allowed_models: Some(vec!["small-model".to_owned(), "code-model".to_owned()]),
            ..LlmAccessScope::default()
        };
        assert!(listed.permits_model("small-model"));
        assert!(listed.permits_model("code-model"));
        assert!(!listed.permits_model("big-model"));

        let none_allowed = LlmAccessScope {
            allowed_models: Some(vec![]),
            ..LlmAccessScope::default()
        };
        assert!(
            !none_allowed.permits_model("small-model"),
            "an explicit empty model list must deny every model"
        );
    }

    /// D13.b: scope lookup follows the peer's selector specificity —
    /// the FIRST selector in `peer_selectors` that has an entry wins
    /// (node beats group because the caller lists node first), and a
    /// peer with no entry keeps the unrestricted grant (`None`).
    #[test]
    fn llm_scope_policy_scope_for_prefers_most_specific_selector() {
        let node_scope = LlmAccessScope {
            allowed_models: Some(vec!["small-model".to_owned()]),
            ..LlmAccessScope::default()
        };
        let group_scope = LlmAccessScope {
            allowed_models: Some(vec!["small-model".to_owned(), "big-model".to_owned()]),
            ..LlmAccessScope::default()
        };
        let policy = LlmScopePolicy {
            entries: vec![
                ("group:family".to_owned(), group_scope.clone()),
                ("node:laptop-1".to_owned(), node_scope.clone()),
            ],
        };

        let node_selectors = vec!["node:laptop-1".to_owned(), "group:family".to_owned()];
        assert_eq!(
            policy.scope_for(&node_selectors),
            Some(&node_scope),
            "node entry must win even though the group entry is listed first"
        );

        let group_only_selectors = vec!["node:laptop-2".to_owned(), "group:family".to_owned()];
        assert_eq!(policy.scope_for(&group_only_selectors), Some(&group_scope));

        let unmatched_selectors = vec!["node:laptop-3".to_owned(), "group:guests".to_owned()];
        assert_eq!(
            policy.scope_for(&unmatched_selectors),
            None,
            "no entry means the grant stays unrestricted"
        );
    }

    /// M5: An active node's traffic proceeds to rule evaluation normally.
    #[test]
    fn test_active_node_acl_proceeds_to_rule_evaluation() {
        let set = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:alice".to_owned(),
                dst: "node:active-node".to_owned(),
                protocol: Protocol::Tcp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        let request = ContextualAccessRequest {
            src: "user:alice".to_owned(),
            dst: "node:active-node".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::Mesh,
        };

        let mut membership = MembershipDirectory::default();
        membership.set_node_status("alice-node", MembershipStatus::Active);
        membership.set_node_status("active-node", MembershipStatus::Active);
        membership.set_selector_members("user:alice", ["alice-node"]);

        // Active node — rule evaluation runs and the allow rule fires
        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Allow,
            "active node must proceed to rule evaluation"
        );
    }

    /// POL-03: an empty identity must never be admitted.
    ///
    /// Pre-fix `selector_matches("*", "")` was true and
    /// the former `selector_requires_membership("")` was false, so a request carrying an empty
    /// src or dst skipped the revocation gate entirely and was then admitted by any
    /// wildcard allow rule — a fail-open on absent trust state, which
    /// `CLAUDE.md` §10.4 explicitly forbids ("empty/missing/malformed → deny").
    #[test]
    fn empty_identity_is_never_allowed_pol03() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };

        for (src, dst, label) in [
            ("", "node:b", "empty src"),
            ("node:a", "", "empty dst"),
            ("", "", "both empty"),
        ] {
            let request = AccessRequest {
                src: src.to_owned(),
                dst: dst.to_owned(),
                protocol: Protocol::Tcp,
            };
            assert_eq!(
                set.evaluate(&request),
                Decision::Deny,
                "{label} must be denied even under a wildcard allow rule"
            );

            // And with the membership gate engaged, for the same reason.
            let mut membership = MembershipDirectory::default();
            membership.set_node_status("a", MembershipStatus::Active);
            membership.set_node_status("b", MembershipStatus::Active);
            assert_eq!(
                set.evaluate_with_membership(&request, &membership),
                Decision::Deny,
                "{label} must be denied on the membership-aware path too"
            );
        }
    }

    /// POL-03: a rule whose selector is accidentally empty must be inert, not
    /// dangerously permissive — it must not match an empty request field.
    #[test]
    fn empty_rule_selector_matches_nothing_pol03() {
        let set = PolicySet {
            rules: vec![PolicyRule {
                src: String::new(),
                dst: String::new(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };

        // Both-empty: covered by either half of the guard.
        assert_eq!(
            set.evaluate(&AccessRequest {
                src: String::new(),
                dst: String::new(),
                protocol: Protocol::Tcp,
            }),
            Decision::Deny,
            "an empty rule selector must not match an empty request field"
        );

        // Empty RULE against a NON-empty request. Note this does NOT pin the
        // rule-side guard: an empty rule value fails equality anyway, so a
        // candidate-only guard passes this too (verified by mutation). It is kept
        // as a behavioural assertion of the outcome, not as coverage of that
        // branch — see `selector_matches` for why the branch is retained.
        assert_eq!(
            set.evaluate(&AccessRequest {
                src: "node:a".to_owned(),
                dst: "node:b".to_owned(),
                protocol: Protocol::Tcp,
            }),
            Decision::Deny,
            "an empty rule selector must not match a real identity"
        );
    }

    /// POL-03: the membership gate must independently refuse an empty selector.
    ///
    /// Tested directly because no public path reaches it without
    /// `selector_matches` having already rejected the request — the guard exists so
    /// that a future evaluator which consults membership on its own cannot
    /// reintroduce the fail-open. Removing it left every other test green.
    #[test]
    fn membership_gate_refuses_an_empty_selector_pol03() {
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("a", MembershipStatus::Active);
        assert!(
            !selector_membership_allowed("", &membership),
            "an empty selector is absent trust state and must not pass the gate"
        );
        // A wildcard still passes, so the guard has not broken the normal path.
        assert!(selector_membership_allowed("*", &membership));
    }
}
