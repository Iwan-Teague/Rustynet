#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE1_SOURCE_PATH: &str = "artifacts/perf/phase1/source/performance_samples.ndjson";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let root_dir = repo_root().map_err(|err| {
        report_error(ExitCode::ConfigError, &err);
        ExitCode::ConfigError.as_i32()
    })?;

    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_owned());

    run_command(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[],
    )?;
    run_command(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    let phase1_source_path = resolve_source_path(
        &root_dir,
        env::var_os("RUSTYNET_PHASE1_PERF_SAMPLES_PATH")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| OsString::from(DEFAULT_PHASE1_SOURCE_PATH)),
    );
    if !phase1_source_path.is_file() {
        report_error(
            ExitCode::ConfigError,
            &format!(
                "missing measured phase1 source: {}",
                phase1_source_path.display()
            ),
        );
        return Err(ExitCode::ConfigError.as_i32());
    }
    let phase1_source_path = phase1_source_path
        .to_str()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            report_error(
                ExitCode::ConfigError,
                &format!(
                    "phase1 source path is not valid UTF-8: {}",
                    phase1_source_path.display()
                ),
            );
            ExitCode::ConfigError.as_i32()
        })?;
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-phase1-baseline",
        ],
        Some(&root_dir),
        &[(
            "RUSTYNET_PHASE1_PERF_SAMPLES_PATH",
            phase1_source_path.as_str(),
        )],
    )?;
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-phase3-baseline",
        ],
        Some(&root_dir),
        &[],
    )?;

    // RN-02: the phase-4 dataplane controls (exit-node selection/clear,
    // LAN-route toggle, Magic DNS hostname determinism, tunnel/DNS fail-close)
    // are enforced by the LIVE Phase10Controller path
    // (crates/rustynetd/src/phase10.rs) and the signed-zone builder
    // (crates/rustynet-dns-zone), NOT the removed dead `dataplane.rs` module.
    // Point the gate at the live tests so it validates the code that actually
    // runs in production, not a parallel implementation that never executes.
    run_required_test(
        &root_dir,
        "rustynetd",
        "phase10::tests::set_and_clear_exit_node_track_exit_mode_and_assert_measured_policy",
    )?;
    run_required_test(
        &root_dir,
        "rustynetd",
        "phase10::tests::lan_toggle_requires_toggle_route_advertisement_acl_and_policy",
    )?;
    run_required_test(
        &root_dir,
        "rustynet-dns-zone",
        "tests::bundle_builder_rejects_alias_collision",
    )?;
    run_required_test(
        &root_dir,
        "rustynetd",
        "phase10::tests::full_tunnel_dns_assert_failure_holds_dns_fail_closed_and_blocks_exit_mode",
    )?;
    run_required_test(
        &root_dir,
        "rustynet-policy",
        "contextual_policy_does_not_widen_between_shared_router_and_exit",
    )?;
    run_required_test(
        &root_dir,
        "rustynet-policy",
        "protocol_filter_is_preserved_for_shared_exit_context",
    )?;

    println!("Phase 4 CI gates: PASS");
    Ok(())
}

fn run_required_test(root_dir: &Path, package: &str, test_filter: &str) -> Result<(), i32> {
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "run_required_test",
            "--",
            package,
            test_filter,
        ],
        Some(root_dir),
        &[],
    )
}

fn run_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> Result<(), i32> {
    let mut command = Command::new(program);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command.args(args).stdin(std::process::Stdio::null());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let status = command.status().map_err(|err| {
        report_error(
            ExitCode::TransientFailure,
            &format!("failed to run {program}: {err}"),
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through subprocess exit code so the inner taxonomy
        // bubble (e.g. PolicyReject from a downstream gate) survives.
        Err(status_code(status))
    }
}

fn report_error(code: ExitCode, message: &str) {
    let hint = code.operator_hint();
    if hint.is_empty() {
        eprintln!("error [{code}]: {message}");
    } else {
        eprintln!("error [{code}]: {message}\n  hint: {hint}");
    }
}

fn resolve_source_path(root_dir: &Path, raw: OsString) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        root_dir.join(path)
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
