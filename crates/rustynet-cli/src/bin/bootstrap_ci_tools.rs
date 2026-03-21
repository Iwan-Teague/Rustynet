#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const PINNED_TOOLCHAIN: &str = "1.85.0";
const DEFAULT_SECURITY_TOOLCHAIN: &str = "1.88.0";
const REQUIRED_AUDIT_VERSION_PREFIX: &str = "cargo-audit 0.22.";
const REQUIRED_DENY_VERSION_PREFIX: &str = "cargo-deny 0.19.";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();

    if bootstrap_system_packages_enabled() && command_exists("apt-get", None) {
        install_system_packages()?;
    }

    let mut cargo_bin = cargo_bin_dir_if_present();
    if !command_exists("rustup", cargo_bin.as_deref()) {
        install_rustup(cargo_bin.as_deref())?;
    }
    cargo_bin = cargo_bin_dir_if_present();
    if let Some(dir) = cargo_bin.as_deref() {
        publish_github_path(dir)?;
    }

    run_command(
        "rustup",
        &[
            "toolchain",
            "install",
            PINNED_TOOLCHAIN,
            "--profile",
            "minimal",
            "--component",
            "rustfmt",
            "--component",
            "clippy",
        ],
        cargo_bin.as_deref(),
        None,
        &[],
    )?;
    run_command(
        "rustup",
        &["default", PINNED_TOOLCHAIN],
        cargo_bin.as_deref(),
        None,
        &[],
    )?;

    let security_toolchain = env::var("RUSTYNET_SECURITY_TOOLCHAIN")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_SECURITY_TOOLCHAIN.to_string());
    run_command(
        "rustup",
        &[
            "toolchain",
            "install",
            security_toolchain.as_str(),
            "--profile",
            "minimal",
        ],
        cargo_bin.as_deref(),
        None,
        &[],
    )?;

    if !version_starts_with(
        "cargo-audit",
        &["--version"],
        REQUIRED_AUDIT_VERSION_PREFIX,
        cargo_bin.as_deref(),
    ) {
        let toolchain = format!("+{security_toolchain}");
        run_command(
            "cargo",
            &[
                toolchain.as_str(),
                "install",
                "cargo-audit",
                "--locked",
                "--version",
                "0.22.1",
                "--force",
            ],
            cargo_bin.as_deref(),
            None,
            &[],
        )?;
    }

    if !version_starts_with(
        "cargo-deny",
        &["--version"],
        REQUIRED_DENY_VERSION_PREFIX,
        cargo_bin.as_deref(),
    ) {
        let toolchain = format!("+{security_toolchain}");
        run_command(
            "cargo",
            &[
                toolchain.as_str(),
                "install",
                "cargo-deny",
                "--locked",
                "--force",
            ],
            cargo_bin.as_deref(),
            None,
            &[],
        )?;
    }

    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let audit_db_path = env::var_os("RUSTYNET_AUDIT_DB_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| root_dir.join(".cargo-audit-db"));
    let audit_db = audit_db_path.to_str().ok_or_else(|| {
        eprintln!(
            "advisory db path is not valid UTF-8: {}",
            audit_db_path.display()
        );
        1
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
            "prepare-advisory-db",
            audit_db,
        ],
        cargo_bin.as_deref(),
        Some(root_dir.as_path()),
        &[],
    )?;

    Ok(())
}

fn bootstrap_system_packages_enabled() -> bool {
    env::var("RUSTYNET_CI_BOOTSTRAP_SYSTEM")
        .ok()
        .map(|value| value == "1")
        .unwrap_or(true)
}

fn install_system_packages() -> Result<(), i32> {
    let use_sudo = current_uid().map_err(|err| {
        eprintln!("{err}");
        1
    })? != 0;
    if use_sudo && !command_exists("sudo", None) {
        eprintln!("missing required command: sudo");
        return Err(1);
    }

    run_apt_get(use_sudo, &["update"])?;
    run_apt_get(
        use_sudo,
        &[
            "install",
            "-y",
            "--no-install-recommends",
            "ca-certificates",
            "curl",
            "git",
            "build-essential",
            "pkg-config",
            "python3",
            "iproute2",
            "nftables",
            "wireguard-tools",
        ],
    )
}

fn run_apt_get(use_sudo: bool, args: &[&str]) -> Result<(), i32> {
    let mut command = if use_sudo {
        let mut cmd = Command::new("sudo");
        cmd.arg("apt-get");
        cmd
    } else {
        Command::new("apt-get")
    };
    command
        .args(args)
        .stdin(Stdio::null())
        .env("DEBIAN_FRONTEND", "noninteractive");
    let status = command.status().map_err(|err| {
        eprintln!("failed to execute apt-get: {err}");
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn install_rustup(path_prefix: Option<&Path>) -> Result<(), i32> {
    let path_env = match build_path_env(path_prefix) {
        Ok(path_env) => path_env,
        Err(err) => {
            eprintln!("{err}");
            return Err(1);
        }
    };

    let mut curl_cmd = Command::new("curl");
    curl_cmd
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "-sSf",
            "https://sh.rustup.rs",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(path_value) = &path_env {
        curl_cmd.env("PATH", path_value);
    }
    let mut curl_child = curl_cmd.spawn().map_err(|err| {
        eprintln!("failed to start rustup installer download: {err}");
        1
    })?;
    let curl_stdout = curl_child.stdout.take().ok_or_else(|| {
        eprintln!("failed to capture rustup installer download output");
        1
    })?;

    let mut sh_cmd = Command::new("sh");
    sh_cmd
        .args([
            "-s",
            "--",
            "-y",
            "--profile",
            "minimal",
            "--default-toolchain",
            PINNED_TOOLCHAIN,
        ])
        .stdin(Stdio::from(curl_stdout))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(path_value) = &path_env {
        sh_cmd.env("PATH", path_value);
    }
    let sh_status = sh_cmd.status().map_err(|err| {
        eprintln!("failed to execute rustup installer script: {err}");
        1
    })?;
    let curl_status = curl_child.wait().map_err(|err| {
        eprintln!("failed waiting for rustup installer download command: {err}");
        1
    })?;
    if !curl_status.success() {
        return Err(status_code(curl_status));
    }
    if !sh_status.success() {
        return Err(status_code(sh_status));
    }
    Ok(())
}

fn publish_github_path(cargo_bin: &Path) -> Result<(), i32> {
    let Some(path_file) = env::var_os("GITHUB_PATH").filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&path_file))
        .map_err(|err| {
            eprintln!(
                "failed to open GITHUB_PATH target {}: {err}",
                Path::new(&path_file).display()
            );
            1
        })?;
    writeln!(file, "{}", cargo_bin.display()).map_err(|err| {
        eprintln!(
            "failed to append cargo bin path to GITHUB_PATH file {}: {err}",
            Path::new(&path_file).display()
        );
        1
    })?;
    Ok(())
}

fn run_command(
    program: &str,
    args: &[&str],
    path_prefix: Option<&Path>,
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> Result<(), i32> {
    let mut cmd = Command::new(program);
    if let Some(path_value) = build_path_env(path_prefix).map_err(|err| {
        eprintln!("{err}");
        1
    })? {
        cmd.env("PATH", path_value);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.args(args).stdin(Stdio::null());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let status = cmd.status().map_err(|err| {
        eprintln!(
            "failed to run command: {} {} ({err})",
            program,
            args.join(" ")
        );
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn version_starts_with(
    program: &str,
    args: &[&str],
    expected_prefix: &str,
    path_prefix: Option<&Path>,
) -> bool {
    if !command_exists(program, path_prefix) {
        return false;
    }
    let mut cmd = Command::new(program);
    if let Ok(Some(path_value)) = build_path_env(path_prefix) {
        cmd.env("PATH", path_value);
    }
    let output = match cmd.args(args).stdin(Stdio::null()).output() {
        Ok(output) => output,
        Err(_) => return false,
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.starts_with(expected_prefix)
}

fn current_uid() -> Result<u32, String> {
    let output = Command::new("id")
        .args(["-u"])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to run id -u: {err}"))?;
    if !output.status.success() {
        return Err(format!("id -u failed with status: {}", output.status));
    }
    let uid_text = String::from_utf8_lossy(&output.stdout);
    uid_text
        .trim()
        .parse::<u32>()
        .map_err(|err| format!("failed to parse uid from id -u output '{uid_text}': {err}"))
}

fn cargo_bin_dir_if_present() -> Option<PathBuf> {
    let home = env::var_os("HOME").filter(|value| !value.is_empty())?;
    let path = Path::new(&home).join(".cargo").join("bin");
    if path.is_dir() { Some(path) } else { None }
}

fn command_exists(name: &str, path_prefix: Option<&Path>) -> bool {
    if Path::new(name).components().count() > 1 {
        return Path::new(name).is_file();
    }
    let mut candidates = Vec::new();
    if let Some(prefix) = path_prefix {
        candidates.push(prefix.to_path_buf());
    }
    if let Some(path_var) = env::var_os("PATH") {
        candidates.extend(env::split_paths(&path_var));
    }
    candidates.into_iter().any(|dir| {
        let candidate = dir.join(name);
        candidate.is_file() || is_windows_executable(name, &dir)
    })
}

#[cfg(windows)]
fn is_windows_executable(name: &str, dir: &Path) -> bool {
    dir.join(format!("{name}.exe")).is_file()
}

#[cfg(not(windows))]
fn is_windows_executable(_name: &str, _dir: &Path) -> bool {
    false
}

fn build_path_env(path_prefix: Option<&Path>) -> Result<Option<OsString>, String> {
    let Some(prefix) = path_prefix else {
        return Ok(None);
    };
    let mut paths = vec![prefix.to_path_buf()];
    if let Some(path_var) = env::var_os("PATH") {
        paths.extend(env::split_paths(&path_var));
    }
    let joined = env::join_paths(paths).map_err(|err| {
        format!(
            "failed to build PATH with prefix {}: {err}",
            prefix.display()
        )
    })?;
    Ok(Some(joined))
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
