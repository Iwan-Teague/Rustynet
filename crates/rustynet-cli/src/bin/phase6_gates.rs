#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const REQUIRED_ARTIFACTS: &[&str] = &[
    "artifacts/release/sbom.cargo-metadata.json",
    "artifacts/release/sbom.sha256",
    "artifacts/release/rustynetd.provenance.json",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_string());

    run_command(&root_dir, "cargo", &["fmt", "--all", "--", "--check"], &[])?;
    run_command(
        &root_dir,
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
        &[],
    )?;
    run_command(
        &root_dir,
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        &[],
    )?;
    run_command(
        &root_dir,
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    run_script(&root_dir, "scripts/ci/phase5_gates.sh", &[])?;

    run_required_test(
        &root_dir,
        "rustynet-control",
        "admin::tests::clickjacking_headers_are_hardened",
        &["--all-features"],
    )?;
    run_required_test(
        &root_dir,
        "rustynet-control",
        "admin::tests::privileged_helper_validation_rejects_shell_construction",
        &["--all-features"],
    )?;
    run_required_test(
        &root_dir,
        "rustynet-control",
        "admin::tests::privileged_helper_validation_accepts_argv_only_commands",
        &["--all-features"],
    )?;

    let parity_environment = env::var("RUSTYNET_PHASE6_PARITY_ENVIRONMENT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "ci".to_string());

    if cfg!(target_os = "macos")
        || env::var("RUSTYNET_PHASE6_COLLECT_PARITY").ok().as_deref() == Some("1")
    {
        run_ops_with_env(
            &root_dir,
            "collect-platform-parity-bundle",
            &[(
                "RUSTYNET_PHASE6_PARITY_ENVIRONMENT",
                parity_environment.as_str(),
            )],
            &[],
        )?;
    }

    if env::var("RUSTYNET_PHASE6_GENERATE_PARITY_REPORT")
        .ok()
        .as_deref()
        .unwrap_or("1")
        == "1"
    {
        run_ops_with_env(
            &root_dir,
            "generate-platform-parity-report",
            &[(
                "RUSTYNET_PHASE6_PARITY_ENVIRONMENT",
                parity_environment.as_str(),
            )],
            &[],
        )?;
    }

    run_required_test(
        &root_dir,
        "rustynetd",
        "platform::tests",
        &["--all-features"],
    )?;
    run_command(
        &root_dir,
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "check_phase6_platform_parity",
            "--",
        ],
        &[],
    )?;

    for artifact in REQUIRED_ARTIFACTS {
        require_file(&root_dir.join(artifact))?;
    }

    println!("Phase 6 CI gates: PASS");
    Ok(())
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), i32> {
    let status = Command::new(root_dir.join(script))
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!(
                "failed to execute script {}: {err}",
                root_dir.join(script).display()
            );
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_required_test(
    root_dir: &Path,
    package: &str,
    test_filter: &str,
    extra_args: &[&str],
) -> Result<(), i32> {
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
        .args(extra_args)
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

fn run_ops_with_env(
    root_dir: &Path,
    ops_subcommand: &str,
    env_pairs: &[(&str, &str)],
    args: &[&str],
) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            ops_subcommand,
        ])
        .args(args)
        .envs(env_pairs.iter().copied())
        .status()
        .map_err(|err| {
            eprintln!("failed to run ops {ops_subcommand}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_command(
    root_dir: &Path,
    program: &str,
    args: &[&str],
    env_pairs: &[(&str, &str)],
) -> Result<(), i32> {
    let status = Command::new(program)
        .current_dir(root_dir)
        .args(args)
        .envs(env_pairs.iter().copied())
        .status()
        .map_err(|err| {
            eprintln!("failed to execute command {program}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn require_file(path: &Path) -> Result<(), i32> {
    if path.is_file() {
        Ok(())
    } else {
        eprintln!(
            "missing beta release integrity artifact: {}",
            path.display()
        );
        Err(1)
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
