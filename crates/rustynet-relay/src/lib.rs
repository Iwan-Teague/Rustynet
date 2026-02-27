#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayNode {
    pub id: String,
    pub region: String,
    pub healthy: bool,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelayFleet {
    pub nodes: Vec<RelayNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelaySelectionPolicy {
    pub preferred_region: Option<String>,
    pub allowed_regions: Vec<String>,
}

impl RelayFleet {
    pub fn select_best(&self, preferred_region: Option<&str>) -> Option<RelayNode> {
        self.select_with_policy(&RelaySelectionPolicy {
            preferred_region: preferred_region.map(ToString::to_string),
            allowed_regions: Vec::new(),
        })
    }

    pub fn select_with_policy(&self, policy: &RelaySelectionPolicy) -> Option<RelayNode> {
        let mut candidates = self
            .nodes
            .iter()
            .filter(|node| {
                if policy.allowed_regions.is_empty() {
                    return true;
                }
                policy
                    .allowed_regions
                    .iter()
                    .any(|region| region == &node.region)
            })
            .filter(|node| node.healthy)
            .cloned()
            .collect::<Vec<_>>();
        if let Some(region) = policy.preferred_region.as_deref() {
            let regional = candidates
                .iter()
                .filter(|node| node.region == region)
                .cloned()
                .collect::<Vec<_>>();
            if !regional.is_empty() {
                candidates = regional;
            }
        }

        candidates.sort_by(|left, right| {
            left.latency_ms
                .cmp(&right.latency_ms)
                .then(left.id.cmp(&right.id))
        });
        candidates.into_iter().next()
    }

    pub fn mark_unhealthy(&mut self, relay_id: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|node| node.id == relay_id) {
            node.healthy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RelayFleet, RelayNode, RelaySelectionPolicy};

    #[test]
    fn relay_fleet_prefers_healthy_low_latency_nodes() {
        let fleet = RelayFleet {
            nodes: vec![
                RelayNode {
                    id: "relay-a".to_string(),
                    region: "us-east".to_string(),
                    healthy: true,
                    latency_ms: 20,
                },
                RelayNode {
                    id: "relay-b".to_string(),
                    region: "us-east".to_string(),
                    healthy: true,
                    latency_ms: 10,
                },
            ],
        };
        let selected = fleet
            .select_best(Some("us-east"))
            .expect("relay should be selected");
        assert_eq!(selected.id, "relay-b");
    }

    #[test]
    fn relay_fleet_fails_over_when_primary_is_unhealthy() {
        let mut fleet = RelayFleet {
            nodes: vec![
                RelayNode {
                    id: "relay-a".to_string(),
                    region: "us-east".to_string(),
                    healthy: true,
                    latency_ms: 10,
                },
                RelayNode {
                    id: "relay-b".to_string(),
                    region: "us-west".to_string(),
                    healthy: true,
                    latency_ms: 15,
                },
            ],
        };

        let first = fleet
            .select_best(None)
            .expect("first relay should be selected");
        assert_eq!(first.id, "relay-a");

        fleet.mark_unhealthy("relay-a");
        let second = fleet
            .select_best(None)
            .expect("second relay should be selected");
        assert_eq!(second.id, "relay-b");
    }

    #[test]
    fn relay_selection_policy_respects_allowed_regions() {
        let fleet = RelayFleet {
            nodes: vec![
                RelayNode {
                    id: "relay-a".to_string(),
                    region: "us-east".to_string(),
                    healthy: true,
                    latency_ms: 10,
                },
                RelayNode {
                    id: "relay-b".to_string(),
                    region: "eu-west".to_string(),
                    healthy: true,
                    latency_ms: 5,
                },
            ],
        };

        let policy = RelaySelectionPolicy {
            preferred_region: Some("eu-west".to_string()),
            allowed_regions: vec!["eu-west".to_string()],
        };
        let selected = fleet
            .select_with_policy(&policy)
            .expect("policy-constrained relay should be selected");
        assert_eq!(selected.id, "relay-b");
    }
}
