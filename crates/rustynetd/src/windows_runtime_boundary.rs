#![allow(clippy::result_large_err)]

use crate::key_material::{
    read_passphrase_file, remove_file_if_present, store_passphrase_in_os_secure_store,
};
use crate::windows_ipc::{
    WindowsLocalIpcRole, WindowsPrivilegedRequest, WindowsPrivilegedResponse,
    call_windows_privileged_request, serve_windows_privileged_request_once, windows_ipc_probe,
};
use crate::windows_paths::{
    validate_windows_runtime_acl, validate_windows_runtime_file_path,
    validate_windows_secret_blob_path,
};
use rustynet_windows_native::inspect_file_sddl;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const DEFAULT_SELF_CHECK_TIMEOUT_MS: u64 = 5_000;
const SELF_CHECK_PASSPHRASE: &str = "00112233445566778899aabbccddeeff\n";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WindowsRuntimeBoundaryReport {
    pub schema_version: u32,
    pub pipe_path: String,
    pub secret_blob_path: String,
    pub state_root_acl_validated: bool,
    pub secret_root_acl_validated: bool,
    pub secret_round_trip_ok: bool,
    pub ipc_probe_ok: bool,
    pub inspected_acl_path: String,
    pub inspected_acl_sddl: String,
}

pub fn run_windows_runtime_boundary_check(
    state_root: &Path,
) -> Result<WindowsRuntimeBoundaryReport, String> {
    validate_windows_runtime_file_path(state_root, "state root")?;
    validate_windows_runtime_acl(state_root, "state root")?;

    let secret_root = state_root.join("secrets");
    validate_windows_runtime_file_path(secret_root.as_path(), "secret root")?;
    validate_windows_runtime_acl(secret_root.as_path(), "secret root")?;

    let secret_blob_path = secret_root.join("boundary-check.passphrase.dpapi");
    let pipe_path = PathBuf::from(format!(
        r"\\.\pipe\RustyNet\rustynetd-privileged.check-{}",
        std::process::id()
    ));
    validate_windows_secret_blob_path(
        secret_blob_path.as_path(),
        "boundary check passphrase blob",
    )?;

    let mut secret_round_trip_ok = false;
    let mut ipc_probe_ok = false;
    let mut inspected_acl_sddl = String::new();
    let cleanup_path = secret_blob_path.clone();

    let run_result = (|| -> Result<(), String> {
        write_plaintext_seed_passphrase(secret_blob_path.as_path())?;
        store_passphrase_in_os_secure_store(secret_blob_path.as_path(), None)?;
        let passphrase = read_passphrase_file(secret_blob_path.as_path())?;
        if passphrase.trim() != SELF_CHECK_PASSPHRASE.trim() {
            return Err("Windows DPAPI passphrase round-trip returned unexpected data".to_string());
        }
        secret_round_trip_ok = true;

        let pipe_path_for_server = pipe_path.clone();
        let secret_blob_for_server = secret_blob_path.clone();
        let server = thread::spawn(move || {
            serve_windows_privileged_request_once(
                pipe_path_for_server.as_path(),
                WindowsLocalIpcRole::PrivilegedHelper,
                None,
                |request| match request {
                    WindowsPrivilegedRequest::Probe { protocol_version } => {
                        Ok(WindowsPrivilegedResponse::ProbeAck { protocol_version })
                    }
                    WindowsPrivilegedRequest::InspectRuntimePathAcl { path } => {
                        let request_path = PathBuf::from(&path);
                        validate_windows_secret_blob_path(
                            request_path.as_path(),
                            "inspect-runtime-path-acl path",
                        )?;
                        if request_path != secret_blob_for_server {
                            return Err(format!(
                                "inspect-runtime-path-acl request must stay pinned to the reviewed self-check secret blob {}; got {}",
                                secret_blob_for_server.display(),
                                request_path.display()
                            ));
                        }
                        let sddl = inspect_file_sddl(request_path.as_path()).map_err(|err| {
                            format!(
                                "inspect-runtime-path-acl failed for {}: {err}",
                                request_path.display()
                            )
                        })?;
                        Ok(WindowsPrivilegedResponse::RuntimePathAcl { path, sddl })
                    }
                },
            )
        });

        thread::sleep(Duration::from_millis(100));
        let timeout = Duration::from_millis(DEFAULT_SELF_CHECK_TIMEOUT_MS);
        windows_ipc_probe(
            pipe_path.as_path(),
            WindowsLocalIpcRole::PrivilegedHelper,
            timeout,
        )?;
        ipc_probe_ok = true;

        let response = call_windows_privileged_request(
            pipe_path.as_path(),
            WindowsLocalIpcRole::PrivilegedHelper,
            &WindowsPrivilegedRequest::InspectRuntimePathAcl {
                path: secret_blob_path.display().to_string(),
            },
            timeout,
        )?;
        match response {
            WindowsPrivilegedResponse::RuntimePathAcl { path, sddl } => {
                if path != secret_blob_path.display().to_string() {
                    return Err(format!(
                        "inspect-runtime-path-acl response path mismatch: expected {}, got {path}",
                        secret_blob_path.display()
                    ));
                }
                inspected_acl_sddl = sddl;
            }
            other => {
                return Err(format!(
                    "unexpected Windows privileged response during runtime-boundary check: {other:?}",
                ));
            }
        }

        server
            .join()
            .map_err(|_| "Windows privileged self-check server thread panicked".to_string())??;
        Ok(())
    })();

    let cleanup_result = remove_file_if_present(cleanup_path.as_path());
    if let Err(err) = cleanup_result {
        return Err(format!(
            "Windows runtime-boundary check cleanup failed for {}: {err}",
            cleanup_path.display()
        ));
    }
    run_result?;

    Ok(WindowsRuntimeBoundaryReport {
        schema_version: 1,
        pipe_path: pipe_path.display().to_string(),
        secret_blob_path: secret_blob_path.display().to_string(),
        state_root_acl_validated: true,
        secret_root_acl_validated: true,
        secret_round_trip_ok,
        ipc_probe_ok,
        inspected_acl_path: secret_blob_path.display().to_string(),
        inspected_acl_sddl,
    })
}

fn write_plaintext_seed_passphrase(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "boundary-check passphrase path must include a parent directory: {}",
            path.display()
        )
    })?;
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|err| {
            format!(
                "inspect boundary-check passphrase seed path failed ({}): {err}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "boundary-check passphrase seed path must be a regular file when pre-existing: {}",
                path.display()
            ));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|err| {
            format!(
                "create boundary-check passphrase seed failed ({}): {err}",
                path.display()
            )
        })?;
    file.write_all(SELF_CHECK_PASSPHRASE.as_bytes())
        .map_err(|err| {
            format!(
                "write boundary-check passphrase seed failed ({}): {err}",
                path.display()
            )
        })?;
    file.flush().map_err(|err| {
        format!(
            "flush boundary-check passphrase seed failed ({}): {err}",
            path.display()
        )
    })?;
    validate_windows_runtime_acl(parent, "boundary-check secret root")
}
