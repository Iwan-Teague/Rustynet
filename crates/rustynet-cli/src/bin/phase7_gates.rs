#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const REQUIRED_TESTS: &[(&str, &str, &[&str])] = &[
    (
        "rustynet-control",
        "scale::tests::ha_cluster_fails_over_to_next_healthy_replica",
        &[],
    ),
    (
        "rustynet-control",
        "scale::tests::ha_cluster_rejects_when_no_healthy_replica_exists",
        &[],
    ),
    (
        "rustynet-control",
        "scale::tests::tenant_guard_enforces_isolation_and_delegated_admin_limits",
        &[],
    ),
    (
        "rustynet-control",
        "scale::tests::trust_hardening_fails_closed_when_state_missing_or_mismatched",
        &[],
    ),
    (
        "rustynet-control",
        "scale::tests::trust_hardening_disable_requires_break_glass_secret",
        &[],
    ),
    (
        "rustynet-relay",
        "tests::relay_selection_policy_respects_allowed_regions",
        &[],
    ),
    (
        "rustynet-relay",
        "tests::relay_fleet_fails_over_when_primary_is_unhealthy",
        &[],
    ),
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_string());

    run_cargo(&root_dir, &["fmt", "--all", "--", "--check"], &[])?;
    run_cargo(
        &root_dir,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        &[],
    )?;
    run_cargo(
        &root_dir,
        &["check", "--workspace", "--all-targets", "--all-features"],
        &[],
    )?;
    run_cargo(
        &root_dir,
        &["test", "--workspace", "--all-targets", "--all-features"],
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    run_script(&root_dir, "scripts/ci/phase6_gates.sh", &[])?;

    for (package, test_filter, extra_args) in REQUIRED_TESTS {
        run_required_test(&root_dir, package, test_filter, extra_args)?;
    }

    println!("Phase 7 CI gates: PASS");
    Ok(())
}

fn run_required_test(
    root_dir: &Path,
    package: &str,
    test_filter: &str,
    extra_args: &[&str],
) -> Result<(), i32> {
    let mut args = vec![
        "run".to_string(),
        "--quiet".to_string(),
        "-p".to_string(),
        "rustynet-cli".to_string(),
        "--bin".to_string(),
        "run_required_test".to_string(),
        "--".to_string(),
        package.to_string(),
        test_filter.to_string(),
    ];
    args.extend(extra_args.iter().map(|value| value.to_string()));
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!("failed to run required test package={package} filter={test_filter}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_cargo(root_dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Result<(), i32> {
    let mut command = Command::new("cargo");
    command
        .current_dir(root_dir)
        .args(args)
        .stdin(Stdio::null());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let status = command.status().map_err(|err| {
        eprintln!("failed to run cargo {args:?}: {err}");
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), i32> {
    let status = Command::new(script)
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!("failed to run script {script}: {err}");
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
