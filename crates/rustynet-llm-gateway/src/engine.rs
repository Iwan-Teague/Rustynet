//! Loopback-only inference-engine boundary (LLM design §3.1).
//!
//! The gateway proxies to a co-located engine (llama.cpp / Ollama /
//! vLLM / MLX, …) behind a process boundary. The engine endpoint is
//! validated loopback-only at startup — it must never be reachable
//! from the tunnel or the LAN; only the gateway (which has already
//! done identity + policy + scope gating) talks to it. The engine
//! is swappable behind [`InferenceEngine`]; the gateway contract
//! never leaks engine types.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Fail-closed engine-boundary errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Engine endpoint is not loopback — refused at startup.
    NonLoopbackEndpoint { requested: SocketAddr },
    /// Engine unreachable / process down (health gate trips).
    Unavailable(String),
    /// Requested model is not loaded/served by the engine.
    UnknownModel { model: String },
    /// Generation failed mid-stream.
    GenerationFailed(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NonLoopbackEndpoint { requested } => write!(
                f,
                "inference engine endpoint {requested} refused (loopback-only, fail-closed)"
            ),
            EngineError::Unavailable(reason) => write!(f, "inference engine unavailable: {reason}"),
            EngineError::UnknownModel { model } => write!(f, "unknown model {model:?}"),
            EngineError::GenerationFailed(reason) => write!(f, "generation failed: {reason}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// Validate the engine endpoint at startup: loopback only.
pub fn validate_engine_endpoint(endpoint: SocketAddr) -> Result<SocketAddr, EngineError> {
    let loopback = match endpoint.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if loopback {
        Ok(endpoint)
    } else {
        Err(EngineError::NonLoopbackEndpoint {
            requested: endpoint,
        })
    }
}

/// One streamed completion fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionEvent {
    /// A generated text fragment plus how many model tokens it
    /// consumed (for quota accounting).
    Fragment { text: String, token_count: u64 },
    /// Generation finished normally.
    Done,
}

/// The swappable engine boundary. Implementations proxy to the
/// loopback engine process; [`MockEngine`] stands in for unit tests
/// and for live-lab harness runs that don't need a GPU.
pub trait InferenceEngine {
    /// Models the engine currently serves.
    fn list_models(&self) -> Result<Vec<String>, EngineError>;

    /// Start a completion and return a pull-based event stream. The
    /// gateway drives the iterator so it can cut the stream the
    /// moment authorisation changes mid-generation (revocation
    /// severance) or quota runs out.
    fn stream_completion(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<Box<dyn Iterator<Item = Result<CompletionEvent, EngineError>> + Send>, EngineError>;

    /// Cheap health probe: engine process up and primary model
    /// loaded. Feeds the daemon's fail-closed health gate.
    fn probe_health(&self) -> Result<(), EngineError>;
}

/// Deterministic stand-in engine: echoes the prompt back in fixed
/// fragments. Used by unit tests and as the tiny CPU model for the
/// Linux live-lab evidence run (delta plan §5: GPU not required for
/// the harness).
#[derive(Debug, Clone)]
pub struct MockEngine {
    pub models: Vec<String>,
    pub healthy: bool,
}

impl MockEngine {
    pub fn serving(models: Vec<String>) -> Self {
        Self {
            models,
            healthy: true,
        }
    }
}

impl InferenceEngine for MockEngine {
    fn list_models(&self) -> Result<Vec<String>, EngineError> {
        if !self.healthy {
            return Err(EngineError::Unavailable(
                "mock engine marked down".to_owned(),
            ));
        }
        Ok(self.models.clone())
    }

    fn stream_completion(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<Box<dyn Iterator<Item = Result<CompletionEvent, EngineError>> + Send>, EngineError>
    {
        if !self.healthy {
            return Err(EngineError::Unavailable(
                "mock engine marked down".to_owned(),
            ));
        }
        if !self.models.iter().any(|m| m == model) {
            return Err(EngineError::UnknownModel {
                model: model.to_owned(),
            });
        }
        let fragments: Vec<Result<CompletionEvent, EngineError>> = prompt
            .split_whitespace()
            .map(|word| {
                Ok(CompletionEvent::Fragment {
                    text: format!("{word} "),
                    token_count: 1,
                })
            })
            .chain(std::iter::once(Ok(CompletionEvent::Done)))
            .collect();
        Ok(Box::new(fragments.into_iter()))
    }

    fn probe_health(&self) -> Result<(), EngineError> {
        if self.healthy {
            Ok(())
        } else {
            Err(EngineError::Unavailable(
                "mock engine marked down".to_owned(),
            ))
        }
    }
}
