#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const REQUIRED_TESTS: &[&str] = &[
    "daemon::tests::node_role_command_matrix_is_fail_closed",
    "daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed",
    "daemon::tests::daemon_runtime_blind_exit_role_is_least_privilege",
    "daemon::tests::daemon_runtime_blind_exit_ignores_client_assignment_fields",
    "daemon::tests::daemon_runtime_auto_tunnel_enforcement_applies_and_blocks_manual_mutations",
    "daemon::tests::daemon_runtime_auto_tunnel_allows_relay_exit_with_upstream_exit",
    "daemon::tests::daemon_runtime_enters_restricted_safe_mode_without_trust_evidence",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    for test_filter in REQUIRED_TESTS {
        run_required_test(&root_dir, "rustynetd", test_filter)?;
    }

    println!("Role/Auth matrix gate: PASS");
    Ok(())
}

fn run_required_test(root_dir: &Path, package: &str, test_filter: &str) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "run_required_test",
            "--",
            package,
            test_filter,
        ])
        .status()
        .map_err(|err| {
            eprintln!(
                "failed to execute required test helper for package={package} filter={test_filter}: {err}"
            );
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}
