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
