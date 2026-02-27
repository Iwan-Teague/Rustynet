#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
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

fn selector_matches(rule_value: &str, candidate: &str) -> bool {
    rule_value == "*" || rule_value == candidate
}

#[cfg(test)]
mod tests {
    use super::{AccessRequest, Decision, PolicyRule, PolicySet, Protocol, RuleAction};

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
}
