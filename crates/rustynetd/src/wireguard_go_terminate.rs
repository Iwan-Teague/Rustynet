//! Purpose-built privileged termination of wireguard-go processes (RSA-0033).
//!
//! # Why this builtin exists
//!
//! The privileged helper used to expose a generic `kill -TERM <pid>` program
//! that accepted any pid > 1 (SecurityAuditLedger RSA-0033, CWE-250): any IPC
//! client that passed the peer-credential check could have the root helper
//! signal an arbitrary process. Its only legitimate caller was the macOS
//! command backend's teardown, which kills the wireguard-go processes serving
//! the interface being torn down (`rustynet-backend-wireguard/src/
//! macos_command.rs::terminate_wireguard_go_processes`). wireguard-go
//! daemonizes, so those pids are never helper children — pid scoping cannot
//! express the caller's need. The purpose does.
//!
//! The helper now owns the WHOLE operation: the client names only the
//! interface (`terminate-wireguard-go <interface>`), never a pid. The helper
//! enumerates processes itself with the absolute-path `ps` (argv only, no
//! shell), parses the listing with the same logic the macOS backend uses
//! ([`rustynet_backend_wireguard::parse_wireguard_go_process_entries`]), and
//! signals only processes whose executable is one of the allowlisted
//! wireguard-go paths — exactly the candidates the helper's `wireguard-go`
//! program execs — AND whose interface argument is exactly the validated
//! interface. A process for any other interface, or an executable outside the
//! allowlist, is never signalled. Zero matches is success (nothing to stop).
//! An unparseable listing is an error (fail closed).
//!
//! The interface name is validated with the same rule the macOS backend uses
//! for utun names ([`rustynet_backend_wireguard::
//! validate_macos_wireguard_interface_name`]), so the helper and the backend
//! cannot disagree about what a wireguard-go interface name is.
//!
//! # Residual TOCTOU window
//!
//! A pid read from `ps` can exit and be reused between enumeration and
//! signal. The builtin narrows the window by re-running `ps -p <pid>` for each
//! selected pid immediately before exec'ing `kill` and re-requiring the same
//! allowlisted executable + interface; a vanished or no-longer-matching pid is
//! skipped, never signalled. The window cannot be eliminated with ps alone
//! (a reuse landing inside the microseconds between the re-check and the
//! `kill(2)` call is still possible); full elimination needs signalling by
//! identity (Linux pidfd, macOS pty/proc_info semantics), which no current
//! caller requires. The generic `kill` pid-naming primitive is gone either
//! way — this builtin can only ever name rustynet's own wireguard-go
//! processes.

#[cfg(not(windows))]
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::Command;

use rustynet_backend_wireguard::validate_macos_wireguard_interface_name;
#[cfg(not(windows))]
use rustynet_backend_wireguard::{WireguardGoProcessEntry, parse_wireguard_go_process_entries};

use crate::privileged_helper::PrivilegedCommandOutput;

/// The program token the client sends to the helper (and the helper-less
/// direct path dispatches in-process).
pub const TERMINATE_WIREGUARD_GO_PROGRAM: &str = "terminate-wireguard-go";

/// The absolute `ps` the helper runs to enumerate processes — the same binary
/// the macOS backend's discovery used before RSA-0033. Fixed path: no PATH
/// search, no candidate drift.
#[cfg(not(windows))]
const PS_BINARY_CANDIDATES: &[&str] = &["/bin/ps"];

/// The absolute `kill` the helper execs per selected pid. The same candidate
/// set the removed generic kill program allowed; resolved here, inside the
/// builtin, never named by the client.
#[cfg(not(windows))]
const KILL_BINARY_CANDIDATES: &[&str] = &["/bin/kill", "/usr/bin/kill"];

/// The wireguard-go executables a process must be running for this builtin to
/// signal it: exactly the candidate set the helper's `wireguard-go` program
/// resolves and execs when starting a tunnel. Anything else — a lookalike
/// basename at another path, a different binary for this interface — is
/// skipped.
#[cfg(not(windows))]
const WIREGUARD_GO_BINARY_ALLOWLIST: &[&str] = &[
    "/usr/local/bin/wireguard-go",
    "/opt/homebrew/bin/wireguard-go",
    "/usr/bin/wireguard-go",
];

/// Validate the `terminate-wireguard-go` builtin's argv: exactly one argument,
/// the interface, under the macOS backend's utun rule.
pub fn validate_terminate_wireguard_go_args(args: &[&str]) -> Result<(), String> {
    match args {
        [interface] => validate_macos_wireguard_interface_name(interface),
        _ => Err("unsupported terminate-wireguard-go argument schema".to_owned()),
    }
}

/// Run the builtin with the reviewed production constants. The binaries are
/// resolved and validated exactly like every external program the helper
/// execs (absolute, regular, executable, root-owned, not group/other
/// writable) before anything runs.
#[cfg(not(windows))]
pub(crate) fn execute_terminate_wireguard_go(
    args: &[&str],
) -> Result<PrivilegedCommandOutput, String> {
    let [interface] = args else {
        // Unreachable: both execute_builtin callers run validate_request
        // first, and validate_terminate_wireguard_go_args accepts only the
        // exact one-argument shape.
        return Err("unsupported terminate-wireguard-go argument schema".to_owned());
    };
    run_terminate_wireguard_go(
        resolve_validated_binary(PS_BINARY_CANDIDATES, "ps")?.as_path(),
        resolve_validated_binary(KILL_BINARY_CANDIDATES, "kill")?.as_path(),
        WIREGUARD_GO_BINARY_ALLOWLIST,
        interface,
    )
}

#[cfg(windows)]
pub(crate) fn execute_terminate_wireguard_go(
    _args: &[&str],
) -> Result<PrivilegedCommandOutput, String> {
    // Unix builtin; the helper IPC fails closed on Windows before any command
    // is dispatched, so this arm exists only to keep the dispatcher
    // platform-uniform.
    Err("terminate-wireguard-go is a unix-only in-helper builtin".to_owned())
}

/// Resolve the first candidate that passes the helper's binary validation.
#[cfg(not(windows))]
fn resolve_validated_binary(candidates: &[&str], label: &str) -> Result<PathBuf, String> {
    for candidate in candidates {
        if let Ok(validated) = crate::privileged_helper::validate_privileged_program_binary(
            Path::new(candidate),
            label,
        ) {
            return Ok(validated);
        }
    }
    Err(format!(
        "no validated {label} binary found (tried {})",
        candidates.join(", ")
    ))
}

/// The core executor. `ps`/`kill` binary paths and the wireguard-go allowlist
/// are parameters so tests can point them at controlled stand-ins; the
/// production entry point ([`execute_terminate_wireguard_go`]) pins the
/// reviewed constants above and validates the binaries before running.
/// Arguments are always exec'd argv-only — no shell anywhere on this path.
#[cfg(not(windows))]
pub(crate) fn run_terminate_wireguard_go(
    ps_binary: &Path,
    kill_binary: &Path,
    wireguard_go_allowlist: &[&str],
    interface: &str,
) -> Result<PrivilegedCommandOutput, String> {
    // Defensive re-validation: validate-then-exec is the helper's invariant,
    // and this function is also the direct-path executor.
    validate_macos_wireguard_interface_name(interface)?;
    let listing = exec_capture(ps_binary, &["-axo", "pid=,command="])?;
    if !listing.success() {
        return Err(format!(
            "ps exited with status {} while enumerating processes",
            listing.status
        ));
    }
    let entries = parse_wireguard_go_process_entries(&listing.stdout)?;

    let mut terminated: usize = 0;
    let mut errors: Vec<String> = Vec::new();
    for entry in &entries {
        if !entry_matches_allowlisted_interface(entry, wireguard_go_allowlist, interface) {
            continue;
        }
        // TOCTOU narrowing (see module docs): re-read just this pid
        // immediately before signalling and require the same allowlisted
        // executable + interface. Gone or no-longer-matching → skip.
        match recheck_process_still_matches(
            ps_binary,
            &entry.pid_raw,
            wireguard_go_allowlist,
            interface,
        ) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => return Err(err),
        }
        let signal = exec_capture(kill_binary, &["-TERM", entry.pid_raw.as_str()]);
        match signal {
            Ok(output) if output.success() => terminated += 1,
            Ok(output) => errors.push(format!(
                "kill -TERM {}: exited with status {}: {}",
                entry.pid_raw,
                output.status,
                output.stderr.trim()
            )),
            Err(err) => errors.push(format!("kill -TERM {}: {err}", entry.pid_raw)),
        }
    }

    if errors.is_empty() {
        Ok(PrivilegedCommandOutput {
            status: 0,
            stdout: format!("terminated {terminated} wireguard-go process(es) for {interface}\n"),
            stderr: String::new(),
        })
    } else {
        Err(errors.join("; "))
    }
}

/// True only for a process whose executable is EXACTLY one of the allowlisted
/// wireguard-go paths and whose interface argument is EXACTLY the validated
/// interface.
#[cfg(not(windows))]
fn entry_matches_allowlisted_interface(
    entry: &WireguardGoProcessEntry,
    wireguard_go_allowlist: &[&str],
    interface: &str,
) -> bool {
    entry.interface == interface
        && wireguard_go_allowlist
            .iter()
            .any(|allowed| allowed == &entry.executable)
}

/// Re-read a single pid (`ps -p <pid> -o pid=,command=`) immediately before
/// signalling. A ps that reports nothing for the pid (non-zero exit or empty
/// output) means the process vanished — skip. Output that still shows the
/// same allowlisted executable + interface — signal. Anything else
/// (unparseable, or the pid now belongs to a different process) — skip the
/// signal; only a genuinely unparseable listing is an error.
#[cfg(not(windows))]
fn recheck_process_still_matches(
    ps_binary: &Path,
    pid: &str,
    wireguard_go_allowlist: &[&str],
    interface: &str,
) -> Result<bool, String> {
    let output = exec_capture(ps_binary, &["-p", pid, "-o", "pid=,command="])?;
    if !output.success() || output.stdout.trim().is_empty() {
        return Ok(false);
    }
    match parse_wireguard_go_process_entries(&output.stdout) {
        Ok(entries) => {
            if entries.len() == 1
                && entries[0].pid_raw == pid
                && entry_matches_allowlisted_interface(
                    &entries[0],
                    wireguard_go_allowlist,
                    interface,
                )
            {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(err) => Err(err),
    }
}

/// One argv-only exec with captured streams. No shell, no string
/// interpolation: every element is a discrete argument.
#[cfg(not(windows))]
fn exec_capture(binary: &Path, args: &[&str]) -> Result<PrivilegedCommandOutput, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|err| format!("{} spawn failed: {err}", binary.display()))?;
    Ok(PrivilegedCommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    const REAL_KILL: &str = "/bin/kill";
    const REAL_PS: &str = "/bin/ps";

    fn require_real_ps() -> bool {
        if Path::new(REAL_PS).exists() {
            return true;
        }
        eprintln!("skipping: no {REAL_PS} on this host");
        false
    }

    /// A fake `ps` script. Full listings on `-axo pid=,command=`, single-pid
    /// lookups on `-p <pid> command=` — the two shapes the builtin uses.
    fn write_fake_ps(dir: &Path, full_lines: &[String], per_pid: &[(String, String)]) -> PathBuf {
        let mut script = String::from("#!/bin/sh\n");
        script.push_str("if [ \"$1\" = \"-p\" ]; then\n");
        script.push_str("  pid=\"$2\"\n");
        for (pid, line) in per_pid {
            script.push_str(&format!(
                "  if [ \"$pid\" = \"{pid}\" ]; then\n    printf '%s\\n' '{line}'\n    exit 0\n  fi\n"
            ));
        }
        script.push_str("  exit 1\nfi\n");
        for line in full_lines {
            script.push_str(&format!("printf '%s\\n' '{line}'\n"));
        }
        let path = dir.join("ps");
        let mut file = std::fs::File::create(&path).expect("fake ps should create");
        file.write_all(script.as_bytes())
            .expect("fake ps should write");
        // Same ETXTBSY class as the sleep copy: the script is exec'd directly
        // (shebang) by the builtin, so flush it to disk before any exec.
        file.sync_all().expect("fake ps should sync");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("fake ps should chmod");
        path
    }

    /// Spawn a real, signal-able process: a copy of /bin/sleep holding for an
    /// hour. Its pid is what the fake ps listing reports. Returns None when
    /// the host refuses to run the copied binary at all (macOS AMFI kills a
    /// copied Mach-O whose signature no longer matches, so the copy is
    /// re-signed ad hoc when codesign is available).
    fn spawn_long_lived(dir: &Path, name: &str) -> Option<(PathBuf, std::process::Child)> {
        let fake = dir.join(name);
        // Linux parallel-test race: exec'ing a freshly written binary fails
        // with ETXTBSY ("Text file busy") while any other thread's fork still
        // holds the file's write descriptor. Write the copy explicitly, flush
        // and fsync it, and close it before the exec — then retry the spawn a
        // bounded number of times on ExecutableFileBusy, the standard remedy
        // for this well-known race.
        let mut src = std::fs::File::open("/bin/sleep").expect("sleep should open");
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&fake)
            .expect("sleep copy should succeed");
        std::io::copy(&mut src, &mut dst).expect("sleep copy should succeed");
        dst.flush().expect("sleep copy should flush");
        dst.sync_all().expect("sleep copy should sync");
        drop(dst);
        drop(src);
        // Preserve the exec bit a std::fs::copy would have carried over: a
        // plain create_new() copy lands as 0644 and exec fails with EACCES.
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .expect("sleep copy should chmod");
        // The ad-hoc re-sign exists only for macOS AMFI, which refuses an
        // unsigned copy of a system binary; on Linux the attempt is a doomed
        // fork that merely widens the fd-inheritance window this test is
        // hardening against.
        if cfg!(target_os = "macos") {
            let _ = Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&fake)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        const ETXTBSY_RETRIES: usize = 20;
        let retry_sleep = Duration::from_millis(50);
        let mut spawned = None;
        for attempt in 0..ETXTBSY_RETRIES {
            match Command::new(&fake)
                .arg("3600")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => {
                    spawned = Some(child);
                    break;
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && attempt + 1 < ETXTBSY_RETRIES =>
                {
                    std::thread::sleep(retry_sleep);
                }
                Err(err) => panic!("fake wireguard-go process should spawn: {err}"),
            }
        }
        let mut child = spawned.expect("retry loop exits only via child or panic");
        std::thread::sleep(Duration::from_millis(300));
        if child.try_wait().is_ok_and(|exited| exited.is_some()) {
            let _ = child.wait();
            return None;
        }
        Some((fake, child))
    }

    /// The fake `ps` is exec'd directly (shebang) by the builtin; under a
    /// loaded 16-thread harness another test's fork can still hold this
    /// test's just-written script open for write when the exec lands
    /// (ETXTBSY, "Text file busy") even though this thread flushed, synced
    /// and closed it. Retry the whole builtin call a bounded number of times
    /// on that one error — the same remedy `spawn_long_lived` applies to the
    /// sleep copy. Any other error is returned as-is.
    fn run_terminate_with_etxtbsy_retry(
        ps: &Path,
        kill: &Path,
        allowlist: &[&str],
        interface: &str,
    ) -> Result<PrivilegedCommandOutput, String> {
        let mut out = run_terminate_wireguard_go(ps, kill, allowlist, interface);
        for _ in 0..9 {
            match &out {
                Err(err) if err.contains("Text file busy") => {}
                _ => return out,
            }
            std::thread::sleep(Duration::from_millis(50));
            out = run_terminate_wireguard_go(ps, kill, allowlist, interface);
        }
        out
    }

    fn exited_by_signal(child: &mut std::process::Child) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return status.code().is_none();
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => return false,
            }
        }
    }

    fn still_alive(child: &mut std::process::Child) -> bool {
        matches!(child.try_wait(), Ok(None))
    }

    #[test]
    fn terminate_builtin_kills_matching_interface_process_and_spares_other_interface() {
        if !require_real_ps() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "rn-rsa0033-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be sane")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir should create");

        let Some((fake_utun71, mut victim)) = spawn_long_lived(&dir, "wireguard-go-a") else {
            eprintln!("skipping: host refuses to run the copied sleeper binary");
            return;
        };
        let Some((fake_utun72, mut bystander)) = spawn_long_lived(&dir, "wireguard-go-b") else {
            eprintln!("skipping: host refuses to run the copied sleeper binary");
            return;
        };

        let ps = write_fake_ps(
            &dir,
            &[
                "1 /sbin/launchd".to_owned(),
                format!("{} {} utun71", victim.id(), fake_utun71.display()),
                format!("{} {} utun72", bystander.id(), fake_utun72.display()),
                "999 /opt/homebrew/bin/wireguard-go utun99".to_owned(),
            ],
            &[(
                victim.id().to_string(),
                format!("{} {} utun71", victim.id(), fake_utun71.display()),
            )],
        );

        let result = run_terminate_with_etxtbsy_retry(
            ps.as_path(),
            Path::new(REAL_KILL),
            &[&fake_utun71.display().to_string()],
            "utun71",
        )
        .expect("terminate should succeed for the matching interface");

        assert!(result.success(), "status should be 0: {result:?}");
        assert!(
            result
                .stdout
                .contains("terminated 1 wireguard-go process(es) for utun71"),
            "builtin must report exactly one termination: {:?}",
            result.stdout
        );
        assert!(
            exited_by_signal(&mut victim),
            "utun71 process must die by signal"
        );
        assert!(
            still_alive(&mut bystander),
            "utun72 process must NOT be signalled"
        );
        assert!(
            result
                .stdout
                .contains("terminated 1 wireguard-go process(es) for utun71")
        );

        let _ = bystander.kill();
        let _ = bystander.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_builtin_zero_matches_is_success() {
        let dir = std::env::temp_dir().join(format!(
            "rn-rsa0033-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be sane")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir should create");
        let ps = write_fake_ps(
            &dir,
            &["42 /usr/local/bin/wireguard-go utunOTHER".to_owned()],
            &[],
        );
        let result = run_terminate_with_etxtbsy_retry(
            ps.as_path(),
            Path::new(REAL_KILL),
            &["/usr/local/bin/wireguard-go"],
            "utun7",
        )
        .expect("zero matches must be success (nothing to stop)");
        assert!(result.success());
        assert!(
            result
                .stdout
                .contains("terminated 0 wireguard-go process(es) for utun7")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_builtin_fails_closed_on_unparseable_ps() {
        let dir = std::env::temp_dir().join(format!(
            "rn-rsa0033-badps-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be sane")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir should create");
        let ps = write_fake_ps(
            &dir,
            &["not-a-pid /usr/local/bin/wireguard-go utun7".to_owned()],
            &[],
        );
        let err = run_terminate_with_etxtbsy_retry(
            ps.as_path(),
            Path::new(REAL_KILL),
            &["/usr/local/bin/wireguard-go"],
            "utun7",
        )
        .expect_err("an unparseable ps listing must be an error");
        assert!(err.contains("invalid ps pid value"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_builtin_refuses_bad_interface_before_any_exec() {
        // The ps path does not even exist: if the builtin attempted ANY exec
        // the error would be a spawn failure, not the interface rejection.
        let err = run_terminate_wireguard_go(
            Path::new("/nonexistent/ps"),
            Path::new("/nonexistent/kill"),
            &["/usr/local/bin/wireguard-go"],
            "en0",
        )
        .expect_err("a non-utun interface must be refused");
        assert!(
            err.contains("must start with utun"),
            "refusal must be the interface rule, got: {err}"
        );

        let err = run_terminate_wireguard_go(
            Path::new("/nonexistent/ps"),
            Path::new("/nonexistent/kill"),
            &["/usr/local/bin/wireguard-go"],
            "utun",
        )
        .expect_err("a digit-less utun name must be refused");
        assert!(
            err.contains("utun followed by digits"),
            "refusal must be the interface rule, got: {err}"
        );

        let err = run_terminate_wireguard_go(
            Path::new("/nonexistent/ps"),
            Path::new("/nonexistent/kill"),
            &["/usr/local/bin/wireguard-go"],
            "utun7; rm -rf /",
        )
        .expect_err("a metacharacter-bearing name must be refused");
        assert!(
            err.contains("must start with utun") || err.contains("invalid characters"),
            "{err}"
        );
    }

    #[test]
    fn terminate_builtin_skips_pid_that_vanished_or_was_reused() {
        let dir = std::env::temp_dir().join(format!(
            "rn-rsa0033-recheck-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be sane")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir should create");

        // Full listing claims pid 777 runs the allowlisted binary for utun7,
        // but the per-pid re-check reports the pid GONE (ps exits 1) and pid
        // 888 now belonging to a DIFFERENT process. Neither may be signalled.
        let ps = write_fake_ps(
            &dir,
            &[
                "777 /usr/local/bin/wireguard-go utun7".to_owned(),
                "888 /usr/local/bin/wireguard-go utun7".to_owned(),
            ],
            // -p lookups: 777 → nothing (exit 1); 888 → a wireguard-go binary
            // for a DIFFERENT interface (the pid was reused).
            &[(
                "888".to_owned(),
                "888 /usr/local/bin/wireguard-go utun9".to_owned(),
            )],
        );

        let result = run_terminate_with_etxtbsy_retry(
            ps.as_path(),
            Path::new(REAL_KILL),
            &["/usr/local/bin/wireguard-go"],
            "utun7",
        )
        .expect("vanished/reused pids are skipped, not errors");
        assert!(result.success());
        assert!(
            result
                .stdout
                .contains("terminated 0 wireguard-go process(es) for utun7")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_builtin_reports_a_failed_kill() {
        // A kill that runs but exits non-zero must be reported as an error,
        // never swallowed as success (RSA-0033 review: attack item 8).
        let dir = std::env::temp_dir().join(format!(
            "rn-rsa0033-failkill-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be sane")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir should create");
        let ps = write_fake_ps(
            &dir,
            &["777 /usr/local/bin/wireguard-go utun7".to_owned()],
            &[(
                "777".to_owned(),
                "777 /usr/local/bin/wireguard-go utun7".to_owned(),
            )],
        );
        let kill = dir.join("kill");
        std::fs::write(&kill, "#!/bin/sh\nexit 3\n").expect("fake kill should write");
        std::fs::set_permissions(&kill, std::fs::Permissions::from_mode(0o755))
            .expect("fake kill should chmod");
        let err = run_terminate_with_etxtbsy_retry(
            ps.as_path(),
            &kill,
            &["/usr/local/bin/wireguard-go"],
            "utun7",
        )
        .expect_err("a failed kill must be an error");
        assert!(
            err.contains("kill -TERM 777") && err.contains("status 3"),
            "the failure must name the pid and the kill status: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_builtin_runs_real_ps_and_reports_zero_matches() {
        // The real /bin/ps path end to end (no matching processes on a test
        // host): real exec, real parse, success with nothing signalled.
        if !require_real_ps() {
            return;
        }
        let result = run_terminate_wireguard_go(
            Path::new(REAL_PS),
            Path::new(REAL_KILL),
            &["/usr/local/bin/wireguard-go"],
            "utun424242",
        )
        .expect("real ps enumeration should succeed");
        assert!(result.success());
        assert!(
            result
                .stdout
                .contains("terminated 0 wireguard-go process(es) for utun424242")
        );
    }

    #[test]
    fn validate_args_enforces_single_utun_interface() {
        assert!(validate_terminate_wireguard_go_args(&["utun7"]).is_ok());
        assert!(validate_terminate_wireguard_go_args(&["utun1234567890"]).is_ok());
        assert!(validate_terminate_wireguard_go_args(&[]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["utun7", "-9"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["en0"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["utun"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["utun7x"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["utun7; rm -rf /"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["utun7 utun8"]).is_err());
        assert!(validate_terminate_wireguard_go_args(&["x".repeat(16).as_str()]).is_err());
    }
}
