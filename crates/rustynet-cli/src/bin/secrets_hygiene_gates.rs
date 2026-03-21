#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_COMMANDS: &[&str] = &["cargo", "git"];
const REQUIRED_TESTS: &[(&str, &str)] = &[
    (
        "rustynet-control",
        "operations::tests::redaction_covers_all_ingestion_paths",
    ),
    (
        "rustynet-control",
        "operations::tests::structured_logger_never_writes_cleartext_secrets",
    ),
    (
        "rustynet-control",
        "token_claims_debug_redacts_sensitive_fields",
    ),
    (
        "rustynet-control",
        "throwaway_credential_debug_redacts_sensitive_fields",
    ),
    (
        "rustynetd",
        "daemon::tests::validate_file_security_rejects_group_writable_parent_directory",
    ),
    (
        "rustynetd",
        "daemon::tests::validate_file_security_rejects_symlink_parent_directory",
    ),
    (
        "rustynetd",
        "daemon::tests::passphrase_permission_mask_accepts_systemd_runtime_credential_mode",
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_removes_target_file",
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_rejects_directory",
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_removes_symlink_without_following_target",
    ),
    (
        "rustynet-cli",
        "signing_key_loader_rejects_group_readable_file",
    ),
    ("rustynet-cli", "signing_key_loader_rejects_symlink_path"),
    ("rustynet-cli", "signing_key_loader_accepts_owner_only_file"),
    ("rustynet-cli", "secure_remove_file_rejects_directory"),
    ("rustynet-cli", "secure_remove_file_removes_target_file"),
    (
        "rustynet-cli",
        "create_secure_temp_file_sets_owner_only_mode",
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
    let _args: Vec<OsString> = env::args_os().skip(1).collect();
    let root_dir = match find_root_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            return Err(1);
        }
    };

    for command in REQUIRED_COMMANDS {
        require_command(command)?;
    }

    for (package, test_filter) in REQUIRED_TESTS {
        run_required_test(package, test_filter)?;
    }

    run_command(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--",
        "ops",
        "check-secrets-hygiene",
        "--root",
        root_dir.to_str().ok_or_else(|| {
            eprintln!("repository root is not valid UTF-8: {}", root_dir.display());
            1
        })?,
    ])?;

    println!("Secrets hygiene gate: PASS");
    Ok(())
}

fn find_root_dir() -> Result<PathBuf, String> {
    let exe =
        env::current_exe().map_err(|err| format!("failed to resolve current executable: {err}"))?;
    let mut dir = exe
        .parent()
        .ok_or_else(|| {
            format!(
                "failed to resolve executable parent directory: {}",
                exe.display()
            )
        })?
        .to_path_buf();

    loop {
        if dir.join("Cargo.toml").is_file()
            && dir.join("scripts/ci/secrets_hygiene_gates.sh").is_file()
        {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("failed to locate repository root from current executable".to_string());
        }
    }
}

fn require_command(cmd: &str) -> Result<(), i32> {
    let check = format!("command -v {cmd} >/dev/null 2>&1");
    let status = Command::new("sh")
        .args(["-c", check.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(exit_status) if exit_status.success() => Ok(()),
        Ok(_) | Err(_) => {
            eprintln!("missing required command: {cmd}");
            Err(1)
        }
    }
}

fn run_required_test(package: &str, test_filter: &str) -> Result<(), i32> {
    let tmp_output = TempOutputGuard::create().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let output_file = OpenOptions::new()
        .write(true)
        .open(tmp_output.path())
        .map_err(|err| {
            eprintln!(
                "failed to open required test output file ({}): {err}",
                tmp_output.path().display()
            );
            1
        })?;
    let status = Command::new("cargo")
        .args(["test", "-p", package, test_filter])
        .args(["--", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output_file.try_clone().map_err(|err| {
            eprintln!(
                "failed to clone required test output file handle ({}): {err}",
                tmp_output.path().display()
            );
            1
        })?))
        .stderr(Stdio::from(output_file))
        .spawn()
        .map_err(|err| {
            eprintln!("failed to run cargo test for package={package} filter={test_filter}: {err}");
            1
        })?
        .wait()
        .map_err(|err| {
            eprintln!(
                "failed to wait for cargo test for package={package} filter={test_filter}: {err}"
            );
            1
        })?;

    if !status.success() {
        dump_file_to_stderr(tmp_output.path())?;
        eprintln!("required test failed: package={package} filter={test_filter}");
        return Err(1);
    }

    dump_file_to_stdout(tmp_output.path())?;
    verify_required_test_output(tmp_output.path(), package, test_filter)
}

fn verify_required_test_output(output: &Path, package: &str, test_filter: &str) -> Result<(), i32> {
    let status = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "verify-required-test-output",
            "--output",
            output.to_str().ok_or_else(|| {
                eprintln!(
                    "required test output path is not valid UTF-8: {}",
                    output.display()
                );
                1
            })?,
            "--package",
            package,
            "--test-filter",
            test_filter,
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!(
                "failed to run required test verification for package={package} filter={test_filter}: {err}"
            );
            1
        })?;

    if status.success() { Ok(()) } else { Err(1) }
}

fn run_command(args: &[&str]) -> Result<(), i32> {
    let status = Command::new("cargo")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to run cargo {}: {err}", args.join(" "));
            1
        })?;

    if status.success() { Ok(()) } else { Err(1) }
}

struct TempOutputGuard {
    path: PathBuf,
}

impl TempOutputGuard {
    fn create() -> Result<Self, String> {
        let temp_dir = env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure while creating temp file: {err}"))?
            .as_nanos();

        for attempt in 0..100u64 {
            let candidate = temp_dir.join(format!(
                "rustynet-required-test-{pid}-{nanos}-{attempt}.log"
            ));
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&candidate)
            {
                Ok(_) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to create required test output file ({}): {err}",
                        candidate.display()
                    ));
                }
            }
        }

        Err("failed to create required test output file after exhausting unique paths".to_string())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempOutputGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn dump_file_to_stdout(path: &Path) -> Result<(), i32> {
    let mut file = File::open(path).map_err(|err| {
        eprintln!(
            "failed to read required test output file ({}): {err}",
            path.display()
        );
        1
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|err| {
        eprintln!(
            "failed to read required test output file ({}): {err}",
            path.display()
        );
        1
    })?;
    io::stdout().write_all(&buffer).map_err(|err| {
        eprintln!("failed to write required test output to stdout: {err}");
        1
    })?;
    io::stdout().flush().map_err(|err| {
        eprintln!("failed to flush stdout: {err}");
        1
    })
}

fn dump_file_to_stderr(path: &Path) -> Result<(), i32> {
    let mut file = File::open(path).map_err(|err| {
        eprintln!(
            "failed to read required test output file ({}): {err}",
            path.display()
        );
        1
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|err| {
        eprintln!(
            "failed to read required test output file ({}): {err}",
            path.display()
        );
        1
    })?;
    io::stderr().write_all(&buffer).map_err(|err| {
        eprintln!("failed to write required test output to stderr: {err}");
        1
    })?;
    io::stderr().flush().map_err(|err| {
        eprintln!("failed to flush stderr: {err}");
        1
    })
}
