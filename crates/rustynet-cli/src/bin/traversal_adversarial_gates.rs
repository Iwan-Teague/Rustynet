#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const REQUIRED_TESTS: &[&str] = &[
    "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
    "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
    "daemon::tests::load_traversal_bundle_rejects_private_srflx_candidate",
    "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
    "traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback",
    // A4: adversarial coordination record hardening
    "traversal::tests::test_a4_forged_signature_coordination_record_rejected",
    "traversal::tests::test_a4_replayed_coordination_record_rejected",
    "traversal::tests::test_a4_candidate_flooding_rejected_no_panic",
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

    println!("Traversal adversarial gate: PASS");
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
