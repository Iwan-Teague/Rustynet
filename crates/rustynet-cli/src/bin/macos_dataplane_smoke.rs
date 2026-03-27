#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const REQUIRED_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "validate_macos_passphrase_source_contract",
        "start.sh",
        "missing macOS passphrase source contract enforcement in start.sh",
    ),
    (
        "configure_macos_binary_path_env",
        "start.sh",
        "missing macOS privileged binary custody enforcement in start.sh",
    ),
    (
        "rustynet ops bootstrap-wireguard-custody",
        "start.sh",
        "missing Rust-backed macOS WireGuard custody bootstrap in start.sh",
    ),
    (
        "rustynet ops restart-runtime-service",
        "start.sh",
        "missing Rust-backed macOS launchd restart path in start.sh",
    ),
    (
        "RUSTYNET_WG_KEY_PASSPHRASE=\"${WG_KEY_PASSPHRASE_PATH}\"",
        "start.sh",
        "missing macOS passphrase placeholder path wiring in start.sh",
    ),
    (
        "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=\"${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}\"",
        "start.sh",
        "missing macOS keychain account wiring in start.sh",
    ),
    (
        "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE=\"${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}\"",
        "start.sh",
        "missing macOS keychain service wiring in start.sh",
    ),
    (
        "install_macos_unprivileged_wireguard_tools",
        "start.sh",
        "insecure macOS unprivileged wireguard fallback is still present",
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
    let _ignored_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    println!("[macos-smoke] validating hardened macOS startup contracts in start.sh");
    for (pattern, target, error_message) in REQUIRED_PATTERNS {
        let should_match = *pattern != "install_macos_unprivileged_wireguard_tools";
        let matched = run_rg(&root_dir, pattern, target)?;
        if should_match && !matched {
            eprintln!("[macos-smoke] {error_message}");
            return Err(1);
        }
        if !should_match && matched {
            eprintln!("[macos-smoke] {error_message}");
            return Err(1);
        }
    }

    let status = Command::new("bash")
        .current_dir(&root_dir)
        .args(["-n", "start.sh"])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("[macos-smoke] failed to run bash -n start.sh: {err}");
            1
        })?;
    if !status.success() {
        eprintln!("[macos-smoke] start.sh syntax check failed");
        return Err(status_code(status));
    }

    println!("[macos-smoke] running targeted macOS dataplane security tests");
    run_required_test(
        &root_dir,
        "rustynetd",
        "phase10::tests::macos_render_pf_rules_enforces_dns_fail_closed_when_enabled",
    )?;
    run_required_test(
        &root_dir,
        "rustynetd",
        "phase10::tests::macos_dns_rule_parser_accepts_port_alias_output",
    )?;
    run_required_test(
        &root_dir,
        "rustynet-backend-wireguard",
        "tests::macos_backend_reports_ipv6_not_supported_until_parity_is_implemented",
    )?;

    Ok(())
}

fn run_rg(root_dir: &Path, pattern: &str, target: &str) -> Result<bool, i32> {
    let status = Command::new("rg")
        .current_dir(root_dir)
        .args(["-F", "-n", pattern, target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("[macos-smoke] failed to execute rg for pattern {pattern}: {err}");
            1
        })?;
    Ok(status.success())
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
            "--all-features",
        ])
        .status()
        .map_err(|err| {
            eprintln!(
                "[macos-smoke] failed to execute required test helper for package={package} filter={test_filter}: {err}"
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
