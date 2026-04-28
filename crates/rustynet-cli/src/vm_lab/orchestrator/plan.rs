#![allow(dead_code)]
use crate::vm_lab::orchestrator::stage::OrchestrationStage;

/// Builds the ordered list of stages for a lab run.
/// Full implementation ships in W5.5 when stage impls exist.
pub struct PlanBuilder;

impl PlanBuilder {
    pub fn new() -> Self {
        PlanBuilder
    }

    pub fn build(self) -> Vec<Box<dyn OrchestrationStage>> {
        vec![]
    }
}

impl Default for PlanBuilder {
    fn default() -> Self {
        PlanBuilder::new()
    }
}
