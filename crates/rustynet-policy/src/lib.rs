#![forbid(unsafe_code)]

use std::collections::HashMap;

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
}

impl MembershipDirectory {
    pub fn set_node_status(&mut self, node_id: impl Into<String>, status: MembershipStatus) {
        self.nodes.insert(node_id.into(), status);
    }

    pub fn node_status(&self, node_id: &str) -> MembershipStatus {
        self.nodes
            .get(node_id)
            .copied()
            .unwrap_or(MembershipStatus::Unknown)
    }

    /// Returns `true` if at least one node has been registered in this
    /// directory.  When the directory is unpopulated (empty) the membership
    /// enforcement gate treats nodes as pre-membership and skips the check so
    /// that deployments that have not yet adopted governance are not broken.
    pub fn is_populated(&self) -> bool {
        !self.nodes.is_empty()
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
/// signed service-access policy. Lookup prefers the most specific
/// selector: an exact peer selector (e.g. `node:laptop-1`) wins over
/// a group selector (e.g. `group:family`); first match wins within
/// each specificity tier (mirrors rule ordering elsewhere).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlmScopePolicy {
    pub entries: Vec<(String, LlmAccessScope)>,
}

impl LlmScopePolicy {
    /// Resolve the effective scope for a peer. `peer_selectors` is
    /// the peer's identity selectors in decreasing specificity
    /// (typically `["node:<id>", "group:<g1>", …]`). Returns `None`
    /// when no entry applies — the grant stays unrestricted.
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
}

#[derive(Debug, Clone, Default)]
pub struct PolicyRolloutController {
    revisions: HashMap<String, ContextualPolicySet>,
    active_revision: Option<String>,
    canary_revision: Option<String>,
}

impl PolicyRolloutController {
    pub fn stage_revision(
        &mut self,
        revision_id: String,
        policy: ContextualPolicySet,
    ) -> Result<(), RolloutError> {
        validate_policy_safety(&policy)?;
        self.revisions.insert(revision_id.clone(), policy);
        self.canary_revision = Some(revision_id);
        Ok(())
    }

    pub fn promote_canary(&mut self) -> Result<(), RolloutError> {
        let Some(canary) = self.canary_revision.clone() else {
            return Err(RolloutError::UnknownRevision);
        };
        self.active_revision = Some(canary);
        self.canary_revision = None;
        Ok(())
    }

    pub fn rollback_to(&mut self, revision_id: &str) -> Result<(), RolloutError> {
        if !self.revisions.contains_key(revision_id) {
            return Err(RolloutError::UnknownRevision);
        }
        self.active_revision = Some(revision_id.to_owned());
        self.canary_revision = None;
        Ok(())
    }

    pub fn active_revision(&self) -> Option<&str> {
        self.active_revision.as_deref()
    }
}

fn validate_policy_safety(policy: &ContextualPolicySet) -> Result<(), RolloutError> {
    let contains_allow_all = policy.rules.iter().any(|rule| {
        rule.src == "*"
            && rule.dst == "*"
            && rule.protocol == Protocol::Any
            && rule.action == RuleAction::Allow
    });
    if contains_allow_all {
        return Err(RolloutError::UnsafeAllowAll);
    }
    Ok(())
}

fn selector_matches(rule_value: &str, candidate: &str) -> bool {
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
    let Some(node_id) = selector_node_id(selector) else {
        return true;
    };
    membership.node_status(node_id) == MembershipStatus::Active
}

fn selector_node_id(selector: &str) -> Option<&str> {
    selector.strip_prefix("node:")
}

#[cfg(test)]
mod tests {
    use super::{
        AccessRequest, ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet,
        Decision, LlmAccessScope, LlmScopePolicy, MembershipDirectory, MembershipStatus,
        PolicyRolloutController, PolicyRule, PolicySet, Protocol, RolloutError, RuleAction,
        TrafficContext,
    };

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
        revoked_membership.set_node_status("node-exit", MembershipStatus::Revoked);
        assert_eq!(
            set.evaluate_with_membership(&request, &revoked_membership),
            Decision::Deny
        );

        let mut active_membership = MembershipDirectory::default();
        active_membership.set_node_status("node-exit", MembershipStatus::Active);
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
        membership.set_node_status("node-a", MembershipStatus::Active);

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
        membership.set_node_status("active-node", MembershipStatus::Active);

        // Active node — rule evaluation runs and the allow rule fires
        assert_eq!(
            set.evaluate_with_membership(&request, &membership),
            Decision::Allow,
            "active node must proceed to rule evaluation"
        );
    }
}
