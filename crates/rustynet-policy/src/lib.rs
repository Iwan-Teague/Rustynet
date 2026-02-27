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
        self.active_revision = Some(revision_id.to_string());
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

#[cfg(test)]
mod tests {
    use super::{
        AccessRequest, ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet,
        Decision, PolicyRolloutController, PolicyRule, PolicySet, Protocol, RolloutError,
        RuleAction, TrafficContext,
    };

    #[test]
    fn policy_defaults_to_deny() {
        let set = PolicySet::default();
        let request = AccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Tcp,
        };

        assert_eq!(set.evaluate(&request), Decision::Deny);
    }

    #[test]
    fn policy_respects_first_match() {
        let set = PolicySet {
            rules: vec![
                PolicyRule {
                    src: "group:family".to_string(),
                    dst: "tag:servers".to_string(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                },
                PolicyRule {
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    protocol: Protocol::Any,
                    action: RuleAction::Deny,
                },
            ],
        };

        let request = AccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Tcp,
        };

        assert_eq!(set.evaluate(&request), Decision::Allow);
    }

    #[test]
    fn contextual_policy_defaults_to_deny_in_shared_contexts() {
        let set = ContextualPolicySet::default();
        let request = ContextualAccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
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
                    src: "group:family".to_string(),
                    dst: "tag:servers".to_string(),
                    protocol: Protocol::Tcp,
                    action: RuleAction::Allow,
                    contexts: vec![TrafficContext::SharedExit],
                },
                ContextualPolicyRule {
                    src: "*".to_string(),
                    dst: "*".to_string(),
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
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        };
        let udp_request = ContextualAccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
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
                src: "group:family".to_string(),
                dst: "tag:servers".to_string(),
                protocol: Protocol::Icmp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedSubnetRouter],
            }],
        };

        let router_request = ContextualAccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Icmp,
            context: TrafficContext::SharedSubnetRouter,
        };
        let exit_request = ContextualAccessRequest {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
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
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![
                    TrafficContext::Mesh,
                    TrafficContext::SharedSubnetRouter,
                    TrafficContext::SharedExit,
                ],
            }],
        };
        let rejected_result = controller.stage_revision("rev-blocked".to_string(), invalid_policy);
        assert_eq!(rejected_result.err(), Some(RolloutError::UnsafeAllowAll));

        let safe_policy_v1 = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_string(),
                dst: "tag:servers".to_string(),
                protocol: Protocol::Tcp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        controller
            .stage_revision("rev-1".to_string(), safe_policy_v1)
            .expect("safe revision should stage");
        controller.promote_canary().expect("canary should promote");
        assert_eq!(controller.active_revision(), Some("rev-1"));

        let safe_policy_v2 = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "group:family".to_string(),
                dst: "tag:servers".to_string(),
                protocol: Protocol::Udp,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh],
            }],
        };
        controller
            .stage_revision("rev-2".to_string(), safe_policy_v2)
            .expect("second safe revision should stage");
        controller.promote_canary().expect("canary should promote");
        assert_eq!(controller.active_revision(), Some("rev-2"));

        controller
            .rollback_to("rev-1")
            .expect("rollback should target known revision");
        assert_eq!(controller.active_revision(), Some("rev-1"));
    }
}
