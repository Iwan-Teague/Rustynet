//! Health reporting for the fail-closed gate (taxonomy ext §5
//! rule 6). The daemon's `service_exposure` controller consumes
//! this: an unhealthy report closes session admission and blocks
//! capability advertisement; it never degrades to an unmediated
//! mode.

use crate::store::{NasStore, NasStoreError};

/// One health observation. `healthy()` is the only signal the
/// exposure gate consumes; the fields exist for diagnostics (ids
/// and booleans only — no paths with user content, no key
/// material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasHealth {
    /// Data root present, a real directory, and writable.
    pub storage_writable: bool,
    /// `.keycheck` sentinel opens under the loaded at-rest key.
    pub key_check_ok: bool,
    /// Refusal reason when unhealthy (operator-readable, no
    /// secrets).
    pub failure_reason: Option<String>,
}

impl NasHealth {
    pub fn healthy(&self) -> bool {
        self.storage_writable && self.key_check_ok && self.failure_reason.is_none()
    }
}

/// Evaluate store health. Any storage or key failure produces an
/// unhealthy report — the caller (daemon health gate) must close
/// admission on it.
pub fn evaluate_health(store: &NasStore) -> NasHealth {
    match store.probe_writable() {
        Ok(()) => NasHealth {
            storage_writable: true,
            key_check_ok: true,
            failure_reason: None,
        },
        Err(err) => NasHealth {
            storage_writable: !matches!(err, NasStoreError::Io(_)),
            key_check_ok: !matches!(err, NasStoreError::KeyCheckFailed(_)),
            failure_reason: Some(err.to_string()),
        },
    }
}
