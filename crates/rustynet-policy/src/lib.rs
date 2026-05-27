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
    allowed_contexts.is_empty() || allowed_contexts.contains(&candidate)
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
        Decision, MembershipDirectory, MembershipStatus, PolicyRolloutController, PolicyRule,
        PolicySet, Protocol, RolloutError, RuleAction, TrafficContext,
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
