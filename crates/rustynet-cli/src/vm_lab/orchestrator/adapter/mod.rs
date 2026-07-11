#![allow(dead_code)]
pub mod android;
pub mod factory;
pub mod ios;
pub mod linux;
pub mod linux_install;
pub mod linux_membership;
pub mod linux_traffic;
pub mod macos;
pub mod macos_install;
pub mod macos_membership;
pub mod macos_traffic;
pub mod node_adapter;
pub mod ssh;
pub mod verifier_key;
pub mod windows;
pub mod windows_install;
pub mod windows_membership;
pub mod windows_traffic;

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
