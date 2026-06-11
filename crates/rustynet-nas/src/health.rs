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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::store::NasStore;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const KEY: [u8; 32] = [0x42; 32];

    /// Unique private temp root per test (no external tempdir dep;
    /// same pattern as the `ops_install_systemd_relay` tests).
    fn test_root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-nas-health-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn healthy_store_reports_healthy() {
        let root = test_root("healthy");
        let store = NasStore::open(&root, KEY).unwrap();
        let health = evaluate_health(&store);
        assert!(health.healthy());
        assert!(health.storage_writable);
        assert!(health.key_check_ok);
        assert!(health.failure_reason.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn removed_data_root_reports_unhealthy_with_reason() {
        let root = test_root("root-removed");
        let store = NasStore::open(&root, KEY).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let health = evaluate_health(&store);
        assert!(!health.healthy());
        assert!(!health.storage_writable);
        let reason = health
            .failure_reason
            .expect("unhealthy report must carry a refusal reason");
        assert!(
            reason.contains("storage io failure"),
            "reason must name the storage failure, got: {reason}"
        );
    }
}
