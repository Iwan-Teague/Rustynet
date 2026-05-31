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

const DEFAULT_SELF_CHECK_TIMEOUT_MS: u64 = 10_000;
const SELF_CHECK_PASSPHRASE: &str = "00112233445566778899aabbccddeeff\n";

/// Maximum attempts the boundary check makes for each one-shot pipe
/// exchange. The one-shot-server + `CallNamedPipeW`-client pattern races on
/// slow hosts: the server can tear the pipe down before the client reads
/// (`ERROR_BROKEN_PIPE` / 109) or the client can reach the pipe before the
/// server's `CreateNamedPipeW` lands (`ERROR_FILE_NOT_FOUND` / 2). Each
/// attempt spawns a fresh server, so a transient race is absorbed.
const SELF_CHECK_MAX_ATTEMPTS: u32 = 5;

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
        store_passphrase_in_os_secure_store(secret_blob_path.as_path(), None, None, false)?;
        let passphrase = read_passphrase_file(secret_blob_path.as_path())?;
        if passphrase.trim() != SELF_CHECK_PASSPHRASE.trim() {
            return Err("Windows DPAPI passphrase round-trip returned unexpected data".to_owned());
        }
        secret_round_trip_ok = true;

        let timeout = Duration::from_millis(DEFAULT_SELF_CHECK_TIMEOUT_MS);

        // The named-pipe server in `serve_windows_privileged_request_once`
        // handles exactly one message and then disconnects.  The boundary
        // check makes two calls (probe + inspect-runtime-path-acl), so
        // each call needs its own freshly-spawned server.  Otherwise the
        // second call hits CallNamedPipeW with ERROR_FILE_NOT_FOUND
        // because the first call already consumed the only message.
        //
        // Each request runs against its own freshly-spawned one-shot server
        // (`serve_windows_privileged_request_once` handles exactly one
        // message and then closes). `run_self_check_exchange` retries the
        // whole exchange on transient named-pipe lifecycle races
        // (`ERROR_FILE_NOT_FOUND` / 2 before `CreateNamedPipeW` lands,
        // `ERROR_BROKEN_PIPE` / 109 on teardown) and, crucially, surfaces a
        // real server-side handler failure as the dominant cause instead of
        // masking it behind the transient client-side pipe error.

        // Step 1: probe
        {
            let probe_spawn = || {
                let pipe_path_for_server = pipe_path.clone();
                thread::spawn(move || {
                    serve_windows_privileged_request_once(
                        pipe_path_for_server.as_path(),
                        WindowsLocalIpcRole::PrivilegedHelper,
                        None,
                        |request| match request {
                            WindowsPrivilegedRequest::Probe { protocol_version } => {
                                Ok(WindowsPrivilegedResponse::ProbeAck { protocol_version })
                            }
                            other => Err(format!(
                                "unexpected request during boundary-check probe: {other:?}"
                            )),
                        },
                    )
                })
            };
            let probe_client = || {
                windows_ipc_probe(
                    pipe_path.as_path(),
                    WindowsLocalIpcRole::PrivilegedHelper,
                    timeout,
                )
            };
            run_self_check_exchange(
                pipe_path.as_path(),
                timeout,
                "probe",
                probe_spawn,
                probe_client,
            )?;
            ipc_probe_ok = true;
        }

        // Step 2: inspect-runtime-path-acl
        let response = {
            let inspect_spawn = || {
                let pipe_path_for_server = pipe_path.clone();
                let secret_blob_for_server = secret_blob_path.clone();
                thread::spawn(move || {
                    serve_windows_privileged_request_once(
                        pipe_path_for_server.as_path(),
                        WindowsLocalIpcRole::PrivilegedHelper,
                        None,
                        |request| match request {
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
                                let sddl =
                                    inspect_file_sddl(request_path.as_path()).map_err(|err| {
                                        format!(
                                            "inspect-runtime-path-acl failed for {}: {err}",
                                            request_path.display()
                                        )
                                    })?;
                                Ok(WindowsPrivilegedResponse::RuntimePathAcl { path, sddl })
                            }
                            other => Err(format!(
                                "unexpected request during boundary-check inspect: {other:?}"
                            )),
                        },
                    )
                })
            };
            let inspect_client = || {
                call_windows_privileged_request(
                    pipe_path.as_path(),
                    WindowsLocalIpcRole::PrivilegedHelper,
                    &WindowsPrivilegedRequest::InspectRuntimePathAcl {
                        path: secret_blob_path.display().to_string(),
                    },
                    timeout,
                )
            };
            run_self_check_exchange(
                pipe_path.as_path(),
                timeout,
                "inspect",
                inspect_spawn,
                inspect_client,
            )?
        };
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

/// Run `op` against a freshly-spawned named-pipe server, retrying when the
/// underlying call returns Windows error 2 (`ERROR_FILE_NOT_FOUND`).  Used by
/// the boundary check to absorb the spawn -> first `CreateNamedPipeW` latency
/// without depending on platform-specific filesystem probing.
fn wait_for_pipe_then<T>(
    timeout: Duration,
    pipe_path: &Path,
    mut op: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    let deadline = std::time::Instant::now() + timeout.max(Duration::from_secs(1));
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if err.contains("Windows error 2") => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Windows runtime-boundary check pipe was not ready within {:?}: {} ({err})",
                        timeout,
                        pipe_path.display()
                    ));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(err),
        }
    }
}

/// Run one boundary-check pipe exchange against a freshly spawned one-shot
/// server, retrying transient named-pipe lifecycle races.
///
/// On each attempt a new server thread is spawned (via `spawn_server`) and
/// the client call (`client_call`) is issued once the pipe is ready. The two
/// results are reconciled so that:
///
/// * a clean exchange returns the client value immediately;
/// * a concrete server-side handler failure (e.g. an authorization or ACL
///   error) is surfaced as the dominant cause rather than being masked
///   behind the transient client-side pipe error from the same broken
///   exchange;
/// * only transient pipe-plumbing errors trigger a retry with a fresh server.
fn run_self_check_exchange<T>(
    pipe_path: &Path,
    timeout: Duration,
    label: &str,
    mut spawn_server: impl FnMut() -> thread::JoinHandle<Result<(), String>>,
    mut client_call: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    let mut last_transient: Option<String> = None;
    for attempt in 0..SELF_CHECK_MAX_ATTEMPTS {
        let server = spawn_server();
        let client_result = wait_for_pipe_then(timeout, pipe_path, &mut client_call);
        let server_result = server
            .join()
            .map_err(|_| format!("Windows privileged self-check {label} server thread panicked"));
        match (client_result, server_result) {
            (Ok(value), Ok(Ok(()))) => return Ok(value),
            // A panicked server thread is never a transient race.
            (_, Err(join_err)) => return Err(join_err),
            // The server handler returned a concrete error. Surface it as the
            // dominant cause unless it is itself a transient pipe-plumbing
            // race, in which case retry with a fresh server.
            (client_result, Ok(Err(server_err))) => {
                if !is_transient_pipe_error(&server_err) {
                    return Err(server_err);
                }
                last_transient = Some(match client_result {
                    Err(client_err) if is_transient_pipe_error(&client_err) => client_err,
                    _ => server_err,
                });
            }
            // The server completed cleanly but the client still errored: a
            // pure client-side race. Retry only on transient pipe errors.
            (Err(client_err), Ok(Ok(()))) => {
                if !is_transient_pipe_error(&client_err) {
                    return Err(client_err);
                }
                last_transient = Some(client_err);
            }
        }
        if attempt + 1 < SELF_CHECK_MAX_ATTEMPTS {
            thread::sleep(Duration::from_millis(100 * (u64::from(attempt) + 1)));
        }
    }
    Err(last_transient.unwrap_or_else(|| {
        format!("Windows runtime-boundary {label} self-check exhausted {SELF_CHECK_MAX_ATTEMPTS} attempts")
    }))
}

/// True when `err` carries a Windows error code (or the pipe-not-ready
/// wrapper) that reflects a transient named-pipe lifecycle race rather than a
/// real authorization/handler failure. Drives the boundary-check retry
/// decision.
fn is_transient_pipe_error(err: &str) -> bool {
    err.contains("pipe was not ready within")
        || mentions_windows_error(err, 2) // ERROR_FILE_NOT_FOUND: pipe not created yet
        || mentions_windows_error(err, 109) // ERROR_BROKEN_PIPE
        || mentions_windows_error(err, 231) // ERROR_PIPE_BUSY: all instances busy
        || mentions_windows_error(err, 233) // ERROR_PIPE_NOT_CONNECTED
}

/// Matches the exact `Windows error <code>` token the native pipe helpers
/// format, without treating `Windows error 2` as a prefix of
/// `Windows error 21` / `231` / ... The code is rendered at the tail of the
/// message or immediately before a `)`, so a match is valid only when the
/// character following the code is not another digit.
fn mentions_windows_error(err: &str, code: u32) -> bool {
    let needle = format!("Windows error {code}");
    let mut search_from = 0;
    while let Some(rel) = err[search_from..].find(&needle) {
        let idx = search_from + rel;
        let after = &err[idx + needle.len()..];
        if !after.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
        search_from = idx + needle.len();
    }
    false
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

#[cfg(test)]
mod tests {
    use super::{is_transient_pipe_error, mentions_windows_error};

    #[test]
    fn mentions_windows_error_matches_exact_code_only() {
        assert!(mentions_windows_error(
            "CallNamedPipeW failed with Windows error 109",
            109
        ));
        assert!(mentions_windows_error(
            "pipe not ready (CallNamedPipeW failed with Windows error 2)",
            2
        ));
        assert!(mentions_windows_error(
            "all pipe instances are busy: Windows error 231",
            231
        ));
        // `Windows error 2` must NOT be treated as a prefix of longer codes.
        assert!(!mentions_windows_error("Windows error 21", 2));
        assert!(!mentions_windows_error("Windows error 231", 2));
        assert!(!mentions_windows_error("Windows error 200", 2));
        // A different code in the message must not match.
        assert!(!mentions_windows_error(
            "GetFileSecurityW failed with Windows error 5",
            2
        ));
    }

    #[test]
    fn is_transient_pipe_error_flags_pipe_lifecycle_races() {
        assert!(is_transient_pipe_error(
            "CallNamedPipeW failed with Windows error 109"
        ));
        assert!(is_transient_pipe_error(
            "CallNamedPipeW failed with Windows error 2"
        ));
        assert!(is_transient_pipe_error(
            "Windows runtime-boundary check pipe was not ready within 10s: \\\\.\\pipe\\x (CallNamedPipeW failed with Windows error 2)"
        ));
        assert!(is_transient_pipe_error(
            "ConnectNamedPipe: Windows error 231"
        ));
        assert!(is_transient_pipe_error("WriteFile: Windows error 233"));
    }

    #[test]
    fn is_transient_pipe_error_ignores_real_handler_failures() {
        // Authorization / ACL / protocol failures must surface, not retry.
        assert!(!is_transient_pipe_error(
            "inspect-runtime-path-acl failed for C:\\x: Access is denied (os error 5)"
        ));
        assert!(!is_transient_pipe_error(
            "inspect-runtime-path-acl request must stay pinned to the reviewed self-check secret blob"
        ));
        assert!(!is_transient_pipe_error(
            "Windows named-pipe client rejected: user_sid=S-1-5-21 local_system=false"
        ));
        assert!(!is_transient_pipe_error(
            "unexpected request during boundary-check probe"
        ));
    }
}
