//! Gateway health for the fail-closed gate (LLM design §3.2): the
//! daemon drops the endpoint when the engine is down, the model is
//! unloaded, or the accelerator is unavailable — never degrades to
//! an unmediated mode.

use crate::engine::InferenceEngine;

/// One health observation (booleans and a reason only — no prompts,
/// no model internals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayHealth {
    pub engine_reachable: bool,
    pub models_served: usize,
    pub failure_reason: Option<String>,
}

impl GatewayHealth {
    pub fn healthy(&self) -> bool {
        self.engine_reachable && self.models_served > 0 && self.failure_reason.is_none()
    }
}

/// Probe the engine boundary. Any failure produces an unhealthy
/// report; the daemon's exposure controller closes admission on it.
pub fn evaluate_health(engine: &dyn InferenceEngine) -> GatewayHealth {
    match engine.probe_health() {
        Ok(()) => match engine.list_models() {
            Ok(models) if !models.is_empty() => GatewayHealth {
                engine_reachable: true,
                models_served: models.len(),
                failure_reason: None,
            },
            Ok(_) => GatewayHealth {
                engine_reachable: true,
                models_served: 0,
                failure_reason: Some("engine serves no models".to_owned()),
            },
            Err(err) => GatewayHealth {
                engine_reachable: true,
                models_served: 0,
                failure_reason: Some(err.to_string()),
            },
        },
        Err(err) => GatewayHealth {
            engine_reachable: false,
            models_served: 0,
            failure_reason: Some(err.to_string()),
        },
    }
}
