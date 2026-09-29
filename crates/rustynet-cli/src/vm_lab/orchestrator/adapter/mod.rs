#![allow(dead_code)]
pub mod android;
pub mod factory;
pub mod ios;
pub mod linux;
pub mod linux_install;
pub mod linux_membership;
pub mod linux_traffic;
pub mod macos;
pub mod macos_exit_traffic;
pub mod macos_install;
pub mod macos_membership;
pub mod macos_traffic;
pub mod node_adapter;
pub mod ssh;
pub mod validated_args;
pub mod verifier_key;
pub mod windows;
pub mod windows_install;
pub mod windows_membership;
pub mod windows_traffic;

/// The ONLY sanctioned `<alias>-bootstrap` node-id mint (QH-68 class;
/// `NodeEngineSetupProvenanceAudit_2026-09-09.md` F2).
///
/// At INSTALL time no daemon exists yet to ask for its identity, so the
/// label-derived bootstrap id is unavoidable; the install adapters call this
/// named helper so the mint is explicit and greppable instead of an inline
/// `unwrap_or_else` fallback. At ENFORCE time it is NOT unavoidable —
/// `EnforceBaselineRuntime` is transitively downstream of `CollectPubkeys`,
/// so reaching enforce with `ctx.node_ids` empty means a skip/reuse path
/// bypassed collection — and the enforce paths must fail closed instead of
/// inventing an identity (see `linux_install::enforce_daemon`,
/// `macos_install::enforce_daemon`).
pub(crate) fn mint_bootstrap_node_id(alias: &str) -> String {
    format!("{alias}-bootstrap")
}

/// Unique per-invocation token for adapter- and stage-owned temporary paths
/// (bundle-issuer env files and issue dirs, source-archive staging). The pid
/// alone collided across parallel issuances in one process — the test harness
/// runs many of them as threads — where one thread's write/scp/tar clobbered
/// another's in-flight file, minting empty verifier keys (observed on a
/// 16-thread lab host). The pid keeps the name debuggable; nanos plus a
/// monotonic counter separate calls landing in the same nanosecond (the
/// `TEMP_SEQUENCE` precedent in `orchestrator::context`).
pub(crate) fn unique_temp_token() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}_{:x}_{:x}",
        std::process::id(),
        nanos,
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Create a collision-free, owner-only temporary file for parallel adapter
/// workers. The caller removes the persisted path after transfer.
pub(super) fn write_secure_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, crate::vm_lab::orchestrator::error::AdapterError> {
    use std::io::Write;

    let mut file = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile()
        .map_err(|err| crate::vm_lab::orchestrator::error::AdapterError::Io {
            message: format!("create temp file failed: {err}"),
        })?;
    file.write_all(content).map_err(|err| {
        crate::vm_lab::orchestrator::error::AdapterError::Io {
            message: format!("write temp file failed: {err}"),
        }
    })?;
    file.flush()
        .map_err(|err| crate::vm_lab::orchestrator::error::AdapterError::Io {
            message: format!("flush temp file failed: {err}"),
        })?;
    let (_open_file, path) =
        file.keep()
            .map_err(|err| crate::vm_lab::orchestrator::error::AdapterError::Io {
                message: format!("persist temp file failed: {err}"),
            })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::unique_temp_token;

    /// Parallel issuances in one test process share the pid; the token must
    /// still separate every call, or two threads clobber each other's
    /// in-flight env file / issue dir / staging tarball again.
    #[test]
    fn unique_temp_token_never_repeats() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(unique_temp_token()), "token repeated");
        }
        assert!(
            unique_temp_token().starts_with(&format!("{}_", std::process::id())),
            "token must keep the pid prefix for debuggability"
        );
    }
}
