#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_COMMANDS: &[&str] = &["cargo", "git"];
/// (package, test filter, extra cargo args). The extra args exist for tests
/// behind default-off cargo features: the vm_lab surface (RNQ-17) only
/// compiles under `--features vm-lab`, so its required tests pass
/// `--all-features` — without it cargo silently runs ZERO tests for the
/// filter and the fail-closed output verifier rejects the run.
const REQUIRED_TESTS: &[(&str, &str, &[&str])] = &[
    (
        "rustynet-control",
        "operations::tests::redaction_covers_all_ingestion_paths",
        &[],
    ),
    (
        "rustynet-control",
        "operations::tests::structured_logger_never_writes_cleartext_secrets",
        &[],
    ),
    (
        "rustynet-control",
        "token_claims_debug_redacts_sensitive_fields",
        &[],
    ),
    (
        "rustynet-control",
        "throwaway_credential_debug_redacts_sensitive_fields",
        &[],
    ),
    (
        "rustynetd",
        "daemon::tests::validate_file_security_rejects_group_writable_parent_directory",
        &[],
    ),
    (
        "rustynetd",
        "daemon::tests::validate_file_security_rejects_symlink_parent_directory",
        &[],
    ),
    (
        "rustynetd",
        "daemon::tests::passphrase_permission_mask_accepts_systemd_runtime_credential_mode",
        &[],
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_removes_target_file",
        &[],
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_rejects_directory",
        &[],
    ),
    (
        "rustynetd",
        "key_material::tests::remove_file_if_present_removes_symlink_without_following_target",
        &[],
    ),
    (
        "rustynet-cli",
        "signing_key_loader_rejects_group_readable_file",
        &[],
    ),
    (
        "rustynet-cli",
        "signing_key_loader_rejects_symlink_path",
        &[],
    ),
    (
        "rustynet-cli",
        "signing_key_loader_accepts_owner_only_file",
        &[],
    ),
    ("rustynet-cli", "secure_remove_file_rejects_directory", &[]),
    (
        "rustynet-cli",
        "secure_remove_file_removes_target_file",
        &[],
    ),
    (
        "rustynet-cli",
        "create_secure_temp_file_sets_owner_only_mode",
        &[],
    ),
    // QH-85 F3: the sink-side spawn scanner and the inventory destination
    // allowlist are part of this gate's proof — the gate must RUN them, not
    // merely rely on their existence in the test suite.
    (
        "rustynet-cli",
        "vm_lab::tests::ssh_sinks_carry_the_destination_guard_and_sshpass_never_takes_a_password_flag",
        &["--all-features"],
    ),
    (
        "rustynet-cli",
        "vm_lab::inventory_ssh_destination_allowlist_tests::ssh_target_allowlist_rejects_hostile_destinations",
        &["--all-features"],
    ),
    (
        "rustynet-cli",
        "vm_lab::inventory_ssh_destination_allowlist_tests::last_known_ip_must_parse_as_an_ip_address",
        &["--all-features"],
    ),
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

/// One failed check, kept so the run can continue and report the rest.
struct GateFailure {
    name: String,
    code: i32,
}

/// Pick the exit code for a run that had several distinct failures.
///
/// Order matters for CI, which branches on the code rather than the log:
/// `PolicyReject` (78) must win over everything, because a CI loop that retries
/// on `TransientFailure` (70) would otherwise retry a run containing a real
/// fail-closed verdict and could eventually "pass" it. `ConfigError` (65) outranks
/// transient for the same reason in miniature: retrying never fixes a config
/// error. Anything unrecognised is treated as at least as severe as transient.
fn worst_exit_code(failures: &[GateFailure]) -> i32 {
    fn severity(code: i32) -> u8 {
        match code {
            c if c == ExitCode::PolicyReject.as_i32() => 3,
            c if c == ExitCode::ConfigError.as_i32() => 2,
            c if c == ExitCode::TransientFailure.as_i32() => 1,
            _ => 1,
        }
    }
    failures
        .iter()
        .map(|failure| failure.code)
        .max_by_key(|code| severity(*code))
        .unwrap_or_else(|| ExitCode::GenericFailure.as_i32())
}

fn run() -> Result<(), i32> {
    let _args: Vec<OsString> = env::args_os().skip(1).collect();
    let root_dir = match find_root_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("error [{}]: {err}", ExitCode::ConfigError);
            return Err(ExitCode::ConfigError.as_i32());
        }
    };

    // Prerequisites still short-circuit, and should: without cargo or git every
    // check below fails for the same uninteresting reason, and reporting sixteen
    // copies of "cargo is missing" is noise, not signal.
    for command in REQUIRED_COMMANDS {
        require_command(command)?;
    }

    // Everything past here accumulates. Previously each check ran with `?`, so the
    // first failure ended the run and hid every check after it — a single
    // long-standing finding (a plain `rm -f` on a passphrase in the macOS
    // bootstrap) meant newly added checks never executed at all, and the gate
    // reported one problem while saying nothing about the rest of the repo. A gate
    // that stops at the first red tells you what broke first, not what is broken.
    let mut failures: Vec<GateFailure> = Vec::new();
    let mut checks_run: usize = 0;

    for (package, test_filter, test_features) in REQUIRED_TESTS {
        checks_run += 1;
        if let Err(code) = run_required_test(package, test_filter, test_features) {
            failures.push(GateFailure {
                name: format!("required test: {package} :: {test_filter}"),
                code,
            });
        }
    }

    checks_run += 1;
    if let Err(code) = run_check_secrets_hygiene(&root_dir) {
        failures.push(GateFailure {
            name: "repo scan: check-secrets-hygiene".to_owned(),
            code,
        });
    }

    checks_run += 1;
    if let Err(code) = run_check_no_tracked_lab_passwords(&root_dir) {
        failures.push(GateFailure {
            name: "repo scan: no inline ssh_password in tracked inventories".to_owned(),
            code,
        });
    }

    checks_run += 1;
    if let Err(code) = run_check_no_privileged_exec_literals(&root_dir) {
        failures.push(GateFailure {
            name: concat!(
                "repo scan: no sudo-echo literals or sshpass password flags ",
                "under crates/ and scripts/"
            )
            .to_owned(),
            code,
        });
    }

    if failures.is_empty() {
        println!("Secrets hygiene gate: PASS ({checks_run} checks)");
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "Secrets hygiene gate: FAIL — {} of {checks_run} checks failed:",
        failures.len()
    );
    for failure in &failures {
        eprintln!("  [{}] {}", failure.code, failure.name);
    }
    eprintln!("Each failure is reported above in full, in the order it ran.");
    Err(worst_exit_code(failures.as_slice()))
}

/// Fail if any tracked VM-lab inventory carries an inline `ssh_password`.
///
/// These inventories live in a public repository, so a password written into one
/// is published to the internet and preserved in git history. Eight of them were
/// committed that way before this gate existed. The passwords are still needed —
/// `sshpass` uses them to prime SSH keys onto guests that have none — so they now
/// live in an untracked `*.secrets.json` sidecar that the loader merges by alias.
/// This gate keeps them from drifting back into the tracked file.
fn run_check_no_tracked_lab_passwords(root_dir: &Path) -> Result<(), i32> {
    // `git ls-files` scopes this to TRACKED files only: the sidecar is ignored and
    // must not trip the gate, which is the entire point of the split.
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", "*vm_lab_inventory*.json"])
        .current_dir(root_dir)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            eprintln!(
                "error [{}]: git ls-files failed: {}",
                ExitCode::ConfigError,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return Err(ExitCode::ConfigError.as_i32());
        }
        Err(err) => {
            eprintln!(
                "error [{}]: git ls-files failed: {err}",
                ExitCode::ConfigError
            );
            return Err(ExitCode::ConfigError.as_i32());
        }
    };

    let mut offenders = Vec::new();
    for rel in String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
    {
        let path = root_dir.join(rel);
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };
        let Some(entries) = value.get("entries").and_then(|e| e.as_array()) else {
            continue;
        };
        for entry in entries {
            // Only a non-empty value is a leak; an explicit null is not.
            let has_secret = entry
                .get("ssh_password")
                .and_then(|p| p.as_str())
                .is_some_and(|p| !p.trim().is_empty());
            if has_secret {
                let alias = entry
                    .get("alias")
                    .and_then(|a| a.as_str())
                    .unwrap_or("<unknown>");
                offenders.push(format!("{rel}: entry {alias}"));
            }
        }
    }

    if !offenders.is_empty() {
        eprintln!(
            "error [{}]: tracked inventory contains inline ssh_password values.",
            ExitCode::PolicyReject
        );
        for offender in &offenders {
            eprintln!("  {offender}");
        }
        eprintln!(
            "  These files are public. Move the value to the untracked sidecar\n  \
             (<inventory-stem>.secrets.json, mode 600, {{\"ssh_passwords\": {{\"<alias>\": \"...\"}}}})\n  \
             and delete it from the tracked JSON. The loader merges it by alias."
        );
        return Err(ExitCode::PolicyReject.as_i32());
    }
    println!("  no inline ssh_password in tracked inventories: ok");
    Ok(())
}

/// QH-85 F3: scan every tracked file under `crates/` and `scripts/` for the two
/// privileged-execution shapes the 2026-09-08 lab-robot audit found in a public
/// repository:
///
/// 1. a guest sudo password fed to `sudo -S` as a source literal — an
///    `echo <literal>` shell line piped into `sudo -S`;
/// 2. a lab SSH password on the local argv — the sshpass password flag in a
///    shell line, or `.arg("-p")` between an `sshpass` spawn and the `ssh` it
///    wraps (after the wrapped `ssh`, `-p` is the legitimate port flag).
///
/// Every needle is assembled from parts so this gate's own source — which lives
/// under `crates/` and IS scanned by its own rule — never contains the raw
/// pattern it searches for (the same self-proof discipline as the vm_lab
/// source-pin scanner). Fail closed: a tracked file that cannot be read as
/// UTF-8 text is a config error, never a skip.
fn privileged_exec_offenders(rel_path: &str, body: &str) -> Vec<String> {
    let q = '"';
    let sudo_pipe = format!("| sudo -{s}", s = "S");
    let echo_single = "echo '";
    let echo_double = "echo \"";
    let shell_sshpass_password = format!("sshpass -{p}", p = "p");
    let rust_sshpass_spawn = format!("Command::new({q}sshpass{q})");
    let rust_password_arg = format!(".arg({q}-p{q})");
    let rust_wrapped_ssh = format!(".arg({q}ssh{q})");

    let mut offenders = Vec::new();
    // Watching is set by a `Command::new("sshpass")` line and ends at the
    // wrapped `.arg("ssh")`: only a `-p` INSIDE that window carries the
    // password — after the wrapped ssh, `-p` is the port flag.
    let mut watching_sshpass = false;
    for (idx, line) in body.lines().enumerate() {
        let line_no = idx + 1;
        if line.contains(&sudo_pipe) && (line.contains(echo_single) || line.contains(echo_double)) {
            offenders.push(format!(
                "{rel_path}:{line_no}: an echo literal feeds `sudo -S` on the same line — \
                 a guest sudo password published in source; deliver it over a stdin channel \
                 from the secrets sidecar instead"
            ));
        }
        if line.contains(&shell_sshpass_password) {
            offenders.push(format!(
                "{rel_path}:{line_no}: `sshpass {p}` puts the lab SSH password on the \
                 process argv; use `sshpass -e` with the SSHPASS environment variable",
                p = "-p"
            ));
        }
        if line.contains(&rust_sshpass_spawn) {
            watching_sshpass = true;
        } else if watching_sshpass {
            if line.contains(&rust_password_arg) {
                offenders.push(format!(
                    "{rel_path}:{line_no}: `.arg(\"-p\")` between an sshpass spawn and its \
                     wrapped ssh puts the password on the argv; use `-e` + SSHPASS"
                ));
            }
            if line.contains(&rust_wrapped_ssh) {
                watching_sshpass = false;
            }
        }
    }
    offenders
}

fn run_check_no_privileged_exec_literals(root_dir: &Path) -> Result<(), i32> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", "crates", "scripts"])
        .current_dir(root_dir)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            eprintln!(
                "error [{}]: git ls-files failed: {}",
                ExitCode::ConfigError,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return Err(ExitCode::ConfigError.as_i32());
        }
        Err(err) => {
            eprintln!(
                "error [{}]: git ls-files failed: {err}",
                ExitCode::ConfigError
            );
            return Err(ExitCode::ConfigError.as_i32());
        }
    };

    let mut offenders = Vec::new();
    for rel in String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
    {
        // Fail closed: an unreadable or non-UTF-8 tracked file stops the scan
        // with a config error. A scan that skips files it cannot read is a
        // gate that lies about what it covered.
        let body = match fs::read_to_string(root_dir.join(rel)) {
            Ok(body) => body,
            Err(err) => {
                eprintln!(
                    "error [{}]: tracked file {rel} cannot be read as text ({err}); \
                     refusing to scan past it",
                    ExitCode::ConfigError
                );
                return Err(ExitCode::ConfigError.as_i32());
            }
        };
        // Rust test modules are CUT from the scan, not exempted wholesale: a
        // negative test's fixture deliberately quotes the defect shape it
        // proves against (the QH-85 F1/F2 fixtures in
        // macos_install.rs::sshpass_prime_commands… are the reason this scan
        // exists), so scanning test code would make every honest fixture an
        // offender. Production code — where a leak would actually ship — is
        // what this rule covers, and the cut starts at the first
        // `#[cfg(test)]`, the same implementation/test slice discipline the
        // vm_lab source-pin scanner enforces. The gate's own source stays
        // fully scanned: it is production code.
        let body: &str = if rel.ends_with(".rs") {
            body.split("#[cfg(test)]").next().unwrap_or(&body)
        } else {
            &body
        };
        offenders.extend(privileged_exec_offenders(rel, body));
    }

    if !offenders.is_empty() {
        eprintln!(
            "error [{}]: privileged-execution literal(s) found under crates/ or scripts/:",
            ExitCode::PolicyReject
        );
        for offender in &offenders {
            eprintln!("  {offender}");
        }
        eprintln!(
            "  sshpass must take the password via `-e` + the SSHPASS environment var;\n  \
             a guest sudo password must reach `sudo -S` over a stdin channel from the\n  \
             untracked secrets sidecar — never as a source literal."
        );
        return Err(ExitCode::PolicyReject.as_i32());
    }
    println!("  no sudo-echo literals or sshpass -p under crates/ and scripts/: ok");
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
            return Err("failed to locate repository root from current executable".to_owned());
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
            eprintln!(
                "error [{}]: missing required command: {cmd}",
                ExitCode::ConfigError
            );
            Err(ExitCode::ConfigError.as_i32())
        }
    }
}

fn run_required_test(package: &str, test_filter: &str, extra_args: &[&str]) -> Result<(), i32> {
    let tmp_output = TempOutputGuard::create().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let output_file = OpenOptions::new()
        .write(true)
        .open(tmp_output.path())
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to open required test output file ({}): {err}",
                ExitCode::ConfigError,
                tmp_output.path().display()
            );
            ExitCode::ConfigError.as_i32()
        })?;
    let status = Command::new("cargo")
        .args(["test", "-p", package, test_filter])
        .args(extra_args)
        .args(["--", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output_file.try_clone().map_err(|err| {
            eprintln!(
                "error [{}]: failed to clone required test output file handle ({}): {err}",
                ExitCode::TransientFailure,
                tmp_output.path().display()
            );
            ExitCode::TransientFailure.as_i32()
        })?))
        .stderr(Stdio::from(output_file))
        .spawn()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to run cargo test for package={package} filter={test_filter}: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?
        .wait()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to wait for cargo test for package={package} filter={test_filter}: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;

    if !status.success() {
        dump_file_to_stderr(tmp_output.path())?;
        // A required hygiene-test failure is a secrets-hygiene policy
        // violation: surface as PolicyReject so retry-only-on-70 CI
        // loops never accidentally retry a real fail-closed verdict.
        eprintln!(
            "error [{}]: required test failed: package={package} filter={test_filter}",
            ExitCode::PolicyReject
        );
        return Err(ExitCode::PolicyReject.as_i32());
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
                    "error [{}]: required test output path is not valid UTF-8: {}",
                    ExitCode::ConfigError,
                    output.display()
                );
                ExitCode::ConfigError.as_i32()
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
                "error [{}]: failed to run required test verification for package={package} filter={test_filter}: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;

    if status.success() {
        Ok(())
    } else {
        // Verification failure = secrets-hygiene contract violation.
        eprintln!(
            "error [{}]: required test verification failed: package={package} filter={test_filter}",
            ExitCode::PolicyReject
        );
        Err(ExitCode::PolicyReject.as_i32())
    }
}

fn run_check_secrets_hygiene(root_dir: &Path) -> Result<(), i32> {
    let root_str = root_dir.to_str().ok_or_else(|| {
        eprintln!(
            "error [{}]: repository root is not valid UTF-8: {}",
            ExitCode::ConfigError,
            root_dir.display()
        );
        ExitCode::ConfigError.as_i32()
    })?;
    let status = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "check-secrets-hygiene",
            "--root",
            root_str,
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to run cargo run ops check-secrets-hygiene: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;

    if status.success() {
        Ok(())
    } else {
        // Secrets-hygiene scan rejected the repo state. Surface as
        // PolicyReject so retry-only-on-70 CI loops do not retry a
        // real secret-leak verdict.
        eprintln!(
            "error [{}]: secrets hygiene check failed",
            ExitCode::PolicyReject
        );
        Err(ExitCode::PolicyReject.as_i32())
    }
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

        Err("failed to create required test output file after exhausting unique paths".to_owned())
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
            "error [{}]: failed to read required test output file ({}): {err}",
            ExitCode::TransientFailure,
            path.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|err| {
        eprintln!(
            "error [{}]: failed to read required test output file ({}): {err}",
            ExitCode::TransientFailure,
            path.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    io::stdout().write_all(&buffer).map_err(|err| {
        eprintln!(
            "error [{}]: failed to write required test output to stdout: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    io::stdout().flush().map_err(|err| {
        eprintln!(
            "error [{}]: failed to flush stdout: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })
}

fn dump_file_to_stderr(path: &Path) -> Result<(), i32> {
    let mut file = File::open(path).map_err(|err| {
        eprintln!(
            "error [{}]: failed to read required test output file ({}): {err}",
            ExitCode::TransientFailure,
            path.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|err| {
        eprintln!(
            "error [{}]: failed to read required test output file ({}): {err}",
            ExitCode::TransientFailure,
            path.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    io::stderr().write_all(&buffer).map_err(|err| {
        eprintln!(
            "error [{}]: failed to write required test output to stderr: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    io::stderr().flush().map_err(|err| {
        eprintln!(
            "error [{}]: failed to flush stderr: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })
}

#[cfg(test)]
mod tests {
    use super::{GateFailure, worst_exit_code};
    use rustynetd::exit_codes::ExitCode;

    fn failure(code: ExitCode) -> GateFailure {
        GateFailure {
            name: "check".to_owned(),
            code: code.as_i32(),
        }
    }

    #[test]
    fn a_policy_reject_outranks_a_transient_failure() {
        // The severity order exists for CI, which branches on the code. A loop
        // that retries on 70 must never retry a run that also contains a real
        // fail-closed verdict, or it can eventually "pass" a leaking repo.
        let failures = vec![
            failure(ExitCode::TransientFailure),
            failure(ExitCode::PolicyReject),
        ];
        assert_eq!(worst_exit_code(&failures), ExitCode::PolicyReject.as_i32());
    }

    #[test]
    fn a_config_error_outranks_a_transient_failure() {
        // Retrying never fixes a config error.
        let failures = vec![
            failure(ExitCode::TransientFailure),
            failure(ExitCode::ConfigError),
        ];
        assert_eq!(worst_exit_code(&failures), ExitCode::ConfigError.as_i32());
    }

    #[test]
    fn a_policy_reject_outranks_a_config_error() {
        let failures = vec![
            failure(ExitCode::ConfigError),
            failure(ExitCode::PolicyReject),
        ];
        assert_eq!(worst_exit_code(&failures), ExitCode::PolicyReject.as_i32());
    }

    #[test]
    fn severity_does_not_depend_on_the_order_checks_happened_to_run() {
        let ascending = vec![
            failure(ExitCode::TransientFailure),
            failure(ExitCode::ConfigError),
            failure(ExitCode::PolicyReject),
        ];
        let descending = vec![
            failure(ExitCode::PolicyReject),
            failure(ExitCode::ConfigError),
            failure(ExitCode::TransientFailure),
        ];
        assert_eq!(worst_exit_code(&ascending), worst_exit_code(&descending));
        assert_eq!(worst_exit_code(&ascending), ExitCode::PolicyReject.as_i32());
    }

    #[test]
    fn a_single_failure_keeps_its_own_code() {
        for code in [
            ExitCode::PolicyReject,
            ExitCode::ConfigError,
            ExitCode::TransientFailure,
        ] {
            assert_eq!(worst_exit_code(&[failure(code)]), code.as_i32());
        }
    }

    #[test]
    fn an_unknown_code_is_never_reported_as_success() {
        // Defensive: a check returning something outside the taxonomy must still
        // produce a non-zero exit.
        let failures = vec![GateFailure {
            name: "odd".to_owned(),
            code: 42,
        }];
        assert_ne!(worst_exit_code(&failures), 0);
    }

    // ── QH-85 F3: the privileged-execution literal scan must be a POSITIVE
    //    scan — a fixture carrying the pattern is REJECTED, and the accepted
    //    (env-var + stdin-channel) shapes pass clean. The fixtures below are
    //    the shapes captured verbatim from commit 6908f20d, with the live
    //    password value REDACTED (rotation is still owed; the value must never
    //    be re-published here). The needles are assembled from parts so this
    //    test source is never itself an offender of the scan it proves.

    /// The captured sudoers-priming remote command: an echo literal piped into
    /// `sudo -S`. MUTATION CAUGHT: reintroducing any `echo '<literal>' |
    /// sudo -S` line under crates/ or scripts/ fails the gate.
    #[test]
    fn gate_rejects_the_captured_sudoers_echo_literal() {
        let captured = format!(
            r#".arg("echo '{REDACTED}' | sudo -{s} bash -c 'echo \"%admin ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/99-rustynet-lab && chmod 0440 /etc/sudoers.d/99-rustynet-lab'");"#,
            REDACTED = "<live-password-redacted-rotation-owed>",
            s = "S",
        );
        let offenders = super::privileged_exec_offenders("fixture.rs", &captured);
        assert!(
            offenders.iter().any(|o| o.contains("echo literal feeds")),
            "the captured echo-literal shape must be rejected, got: {offenders:?}"
        );
    }

    /// The captured `sshpass -p` argv shape. MUTATION CAUGHT: a shell line (or
    /// error message) spawning sshpass with the password flag again passes.
    #[test]
    fn gate_rejects_the_captured_sshpass_shell_flag() {
        let captured = format!(
            "sshpass -{p} \"$LAB_PASSWORD\" ssh -o StrictHostKeyChecking=yes admin@10.0.0.5",
            p = "p",
        );
        let offenders = super::privileged_exec_offenders("fixture.sh", &captured);
        assert!(
            offenders.iter().any(|o| o.contains("process argv")),
            "the captured `sshpass -p` shell shape must be rejected, got: {offenders:?}"
        );
    }

    /// The captured Rust arg-list shape: `.arg("-p").arg(password)` between the
    /// sshpass spawn and the wrapped ssh. MUTATION CAUGHT: reverting the
    /// builder to `cmd.arg("-p").arg(password)` before `.arg("ssh")`.
    #[test]
    fn gate_rejects_the_captured_sshpass_rust_arg_list() {
        let q = '"';
        let captured = format!(
            r#"let mut cmd = std::process::Command::new({q}sshpass{q});
            cmd.arg({q}-p{q})
                .arg(password)
                .arg({q}ssh{q})
                .arg({q}-i{q})
                .arg(identity_file);"#,
            q = q,
        );
        let offenders = super::privileged_exec_offenders("fixture.rs", &captured);
        assert!(
            offenders
                .iter()
                .any(|o| o.contains("between an sshpass spawn")),
            "the captured `.arg(\"-p\")` arg-list shape must be rejected, got: {offenders:?}"
        );
    }

    /// The ACCEPTED shape — the current `sshpass_ssh_command` builder lines:
    /// `-e` + SSHPASS env, `--` before the destination, and `.arg("-p")` only
    /// AFTER the wrapped ssh (the port flag). Must produce no offenders.
    #[test]
    fn gate_accepts_the_env_var_and_stdin_channel_shapes() {
        let q = '"';
        let current_builder = format!(
            r#"let mut cmd = std::process::Command::new({q}sshpass{q});
    cmd.env("SSHPASS", password)
        .arg("-e")
        .arg("ssh")
        .arg("-i")
        .arg(identity_file)
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{{user_flag}}{{host}}"));"#,
            q = q,
        );
        // The accepted sudo path: the password crosses on stdin, not in the
        // remote command string.
        let stdin_channel = concat!(
            "const PRIME_SUDOERS_REMOTE_COMMAND: &str = ",
            "\"sudo -S bash -c 'echo \\\"%admin ALL=(ALL) NOPASSWD: ALL\\\" ",
            "> /etc/sudoers.d/99-rustynet-lab'\";",
        );
        let offenders = super::privileged_exec_offenders(
            "fixture.rs",
            &format!("{current_builder}\n{stdin_channel}"),
        );
        assert!(
            offenders.is_empty(),
            "accepted shapes must pass clean, got: {offenders:?}"
        );
    }
}
