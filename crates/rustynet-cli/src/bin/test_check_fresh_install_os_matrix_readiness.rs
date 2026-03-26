#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn create() -> Result<Self, String> {
        let base_dir = env::temp_dir();
        let pid = std::process::id();
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure while creating temp dir: {err}"))?
            .as_nanos();

        for attempt in 0..100u64 {
            let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = base_dir.join(format!(
                "rustynet-test-check-fresh-install-os-matrix-readiness-{pid}-{now_nanos}-{counter}-{attempt}"
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "create temp dir failed ({}): {err}",
                        candidate.display()
                    ));
                }
            }
        }

        Err("create temp dir failed: exhausted unique path attempts".to_string())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repo root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("clock failure: {err}"))
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

fn run_command(command: &mut Command) -> Result<(), i32> {
    let status = command.status().map_err(|err| {
        eprintln!("failed to run command: {err}");
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run() -> Result<(), i32> {
    let _ignored_args = env::args_os().skip(1).count();
    let repo_root = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let temp_dir = TempDirGuard::create().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let head_commit = Command::new("git")
        .current_dir(&repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| {
            eprintln!("failed to run git rev-parse HEAD: {err}");
            1
        })?;
    if !head_commit.status.success() {
        return Err(status_code(head_commit.status));
    }
    let head_commit = String::from_utf8(head_commit.stdout)
        .map_err(|err| {
            eprintln!("git rev-parse HEAD produced invalid utf-8: {err}");
            1
        })?
        .trim()
        .to_ascii_lowercase();
    let stale_commit = "1111111111111111111111111111111111111111";
    let now_unix = now_unix().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let mut write_fixtures = Command::new("cargo");
    write_fixtures.current_dir(&repo_root);
    write_fixtures.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "write-fresh-install-os-matrix-readiness-fixtures",
    ]);
    write_fixtures
        .arg("--output-dir")
        .arg(temp_dir.path())
        .arg("--head-commit")
        .arg(&head_commit)
        .arg("--stale-commit")
        .arg(stale_commit)
        .arg("--now-unix")
        .arg(now_unix.to_string());
    run_command(&mut write_fixtures)?;

    let mut first_readiness_check = Command::new("cargo");
    first_readiness_check.current_dir(&repo_root);
    first_readiness_check.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "verify-linux-fresh-install-os-matrix-readiness",
    ]);
    first_readiness_check
        .arg("--report-path")
        .arg(temp_dir.path().join("report.json"))
        .arg("--max-age-seconds")
        .arg("604800")
        .arg("--profile")
        .arg("linux")
        .arg("--expected-git-commit")
        .arg(&head_commit);
    run_command(&mut first_readiness_check)?;

    let mut stale_child_check = Command::new("cargo");
    stale_child_check.current_dir(&repo_root);
    stale_child_check.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "verify-linux-fresh-install-os-matrix-readiness",
    ]);
    stale_child_check
        .arg("--report-path")
        .arg(temp_dir.path().join("report_with_stale_child.json"))
        .arg("--max-age-seconds")
        .arg("604800")
        .arg("--profile")
        .arg("linux")
        .arg("--expected-git-commit")
        .arg(&head_commit);
    if stale_child_check
        .status()
        .map_err(|err| {
            eprintln!("failed to run command: {err}");
            1
        })?
        .success()
    {
        eprintln!("expected stale child commit replay fixture to fail readiness validation");
        return Err(1);
    }

    let mut wrapper_success_check = Command::new("cargo");
    wrapper_success_check.current_dir(&repo_root);
    wrapper_success_check.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "check_fresh_install_os_matrix_readiness",
        "--",
    ]);
    wrapper_success_check
        .env(
            "RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH",
            temp_dir.path().join("report.json"),
        )
        .env("RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS", "604800")
        .env("RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE", "linux")
        .env(
            "RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT",
            &head_commit,
        );
    run_command(&mut wrapper_success_check)?;

    let mut wrapper_stale_child_check = Command::new("cargo");
    wrapper_stale_child_check.current_dir(&repo_root);
    wrapper_stale_child_check.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "check_fresh_install_os_matrix_readiness",
        "--",
    ]);
    wrapper_stale_child_check
        .env(
            "RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH",
            temp_dir.path().join("report_with_stale_child.json"),
        )
        .env("RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS", "604800")
        .env("RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE", "linux")
        .env(
            "RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT",
            &head_commit,
        );
    if wrapper_stale_child_check
        .status()
        .map_err(|err| {
            eprintln!("failed to run command: {err}");
            1
        })?
        .success()
    {
        eprintln!(
            "expected wrapper gate to fail when fresh-install report references stale child evidence"
        );
        return Err(1);
    }

    println!("fresh install OS matrix readiness self-test: PASS");
    Ok(())
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}
