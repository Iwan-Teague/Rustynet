#![cfg(feature = "vm-lab")]
//! RNQ-09: real subprocess SIGTERM/SIGINT cleanup proof.
//!
//! Spawns the `rnq09_signal_harness` bin (built only under
//! `--features vm-lab`; see `src/bin/rnq09_signal_harness.rs`), which wires
//! the SAME `register_shutdown_handlers` + `StateMachineRunner`
//! `with_shutdown_flag` seam the production Rust `--node` orchestrator uses
//! (`orchestrator/native.rs`), runs a synthetic 3-stage plan, and — once a
//! REAL OS signal arrives — the process must exhibit the runner's
//! fail-closed contract end to end:
//!   - the stage downstream of the interrupted one is skipped (never
//!     executes)
//!   - the `always_run` cleanup stage still executes (no killswitch/exit-NAT
//!     residue left behind)
//!   - the process never reports success (non-zero exit, no `PASSED`
//!     marker)
//!
//! This is deliberately a real subprocess test, not an in-process
//! simulation: it is the only way to prove `signal_hook`'s registration
//! actually intercepts a real SIGTERM/SIGINT delivered by the OS and that
//! the resulting flag is visible to a stage that is already executing. The
//! companion in-process unit test for the runner's shutdown-skip DECISION
//! itself (pre-set flag -> non-`always_run` stages skip, `always_run`
//! cleanup still runs) lives in
//! `src/vm_lab/orchestrator/runner.rs` (`with_shutdown_flag` tests) —
//! that one is synchronous and deterministic with no real signal involved.
//! Together the two close the gap: this test cannot easily assert on
//! in-process stage outcomes (the runner lives in a subprocess), and the
//! unit test cannot prove real OS signal delivery.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Must match the contract documented at the top of
/// `src/bin/rnq09_signal_harness.rs` exactly.
const MARKER_DIR_ENV: &str = "RNQ09_MARKER_DIR";
const READY_LINE: &str = "READY";
const SHUTDOWN_ACK_LINE: &str = "SHUTDOWN_ACK";
const CLEANUP_MARKER_NAME: &str = "CLEANUP_RAN";
const UNEXPECTED_STAGE_MARKER_NAME: &str = "STAGE_B_RAN";
const PASSED_MARKER_NAME: &str = "PASSED";

/// Generous but bounded: the harness's own poll loop notices a delivered
/// signal within tens of milliseconds, so these timeouts only ever trigger
/// on a genuine hang (CI overload or a real regression), never on expected
/// timing. Anti-flake requirement: the handshake below is a blocking read,
/// NOT a sleep — the bound is a safety net around it, not the synchronization
/// mechanism itself.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const ACK_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Best-effort SIGKILL (argv-only, no shell) — the test's own safety net if
/// the harness ever fails to exit, mirroring the production watchdog's kill
/// idiom (`orchestrator/diagnostics.rs::sigkill_pids`). Never asserted on: a
/// failed kill here just means the process was already gone.
fn best_effort_sigkill(pid: u32) {
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Poll `child.try_wait()` until it reports exit or `bound` elapses.
/// Non-blocking by construction, so a genuine RNQ-09 regression fails only
/// THIS test instead of hanging the whole suite on a plain `child.wait()`.
fn wait_bounded(
    child: &mut std::process::Child,
    bound: Duration,
) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if started.elapsed() >= bound {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs one SIGTERM/SIGINT cleanup case end-to-end against a REAL subprocess:
///  1. spawn `rnq09_signal_harness` with a fresh marker directory
///  2. HANDSHAKE (blocking read, not a sleep) for its `READY` stdout line —
///     this is what makes the test non-flaky: the signal is delivered only
///     once the harness has proven its handlers are installed and stage A is
///     actively polling, never based on a guessed delay
///  3. deliver `signal_flag` (`"-TERM"` or `"-INT"`) to its real pid
///  4. block for the `SHUTDOWN_ACK` line and the process exit
///  5. assert the full fail-closed contract: non-zero exit, cleanup ran, the
///     must-skip stage never ran, and no success marker exists anywhere
fn run_signal_cleanup_case(signal_flag: &str) {
    let marker_dir = tempfile::tempdir().expect("create RNQ-09 marker tempdir");
    let harness_path = env!("CARGO_BIN_EXE_rnq09_signal_harness");

    let mut child = Command::new(harness_path)
        .env(MARKER_DIR_ENV, marker_dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("spawn '{harness_path}': {err}"));
    let pid = child.id();

    // Drain stdout on a background thread, forwarding each line over a
    // channel so the main thread can block on a specific line with a
    // timeout instead of risking an unbounded `read_line`. Drain stderr
    // fully on a second thread purely for diagnostics (and so the harness
    // never blocks on a full pipe if it ever writes more than expected).
    let stdout = child.stdout.take().expect("harness stdout must be piped");
    let stderr = child.stderr.take().expect("harness stderr must be piped");
    let (line_tx, line_rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if line_tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // `line_tx` drops here; further `recv_timeout` calls see Disconnected.
    });
    let stderr_handle = std::thread::spawn(move || -> String {
        use std::io::Read;
        let mut captured = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut captured);
        captured
    });

    // Step 1: HANDSHAKE — block for READY, bounded so a hung/broken harness
    // fails this test instead of wedging the suite.
    match line_rx.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(line) if line == READY_LINE => {}
        Ok(other) => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness's first stdout line was {other:?}, expected {READY_LINE:?} \
                 (pid {pid})"
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness did not print {READY_LINE:?} within {HANDSHAKE_TIMEOUT:?} \
                 (pid {pid})"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness closed stdout before printing {READY_LINE:?} \
                 (early exit/crash, pid {pid})"
            );
        }
    }

    // Step 2: deliver the REAL OS signal now that stage A is definitely
    // mid-poll (argv-only `kill`, no shell — matches the codebase's existing
    // signal-delivery idiom).
    let kill_status = Command::new("kill")
        .arg(signal_flag)
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|err| panic!("send {signal_flag} to pid {pid}: {err}"));
    assert!(
        kill_status.success(),
        "kill {signal_flag} {pid} exited non-zero: {kill_status:?}"
    );

    // Step 3: block for the SHUTDOWN_ACK line the harness prints once its
    // post-run `shutdown_flag.load()` check (mirroring native.rs) observes
    // the signal.
    match line_rx.recv_timeout(ACK_TIMEOUT) {
        Ok(line) if line == SHUTDOWN_ACK_LINE => {}
        Ok(other) => {
            best_effort_sigkill(pid);
            panic!(
                "expected {SHUTDOWN_ACK_LINE:?} after delivering {signal_flag}, got {other:?} \
                 (pid {pid})"
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness did not print {SHUTDOWN_ACK_LINE:?} within {ACK_TIMEOUT:?} of \
                 {signal_flag} (pid {pid})"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness closed stdout without printing {SHUTDOWN_ACK_LINE:?} after \
                 {signal_flag} — it may have exited via the 'shutdown never observed' path \
                 (pid {pid})"
            );
        }
    }

    // Step 4: the process must actually terminate promptly.
    let exit_status = match wait_bounded(&mut child, EXIT_TIMEOUT) {
        Some(status) => status,
        None => {
            best_effort_sigkill(pid);
            panic!(
                "rnq09 harness (pid {pid}) did not exit within {EXIT_TIMEOUT:?} after {signal_flag}"
            );
        }
    };

    let stderr_captured = stderr_handle.join().unwrap_or_default();

    // ── Assertions: the RNQ-09 fail-closed contract ──────────────────────
    assert!(
        !exit_status.success(),
        "harness must exit non-zero after {signal_flag} (a signal-interrupted run has no \
         success outcome to report); got {exit_status:?}; stderr: {stderr_captured}"
    );
    assert!(
        marker_dir.path().join(CLEANUP_MARKER_NAME).exists(),
        "always_run cleanup stage must still write '{CLEANUP_MARKER_NAME}' after {signal_flag} \
         (in production this is the guest killswitch/exit-NAT residue teardown); \
         stderr: {stderr_captured}"
    );
    assert!(
        !marker_dir
            .path()
            .join(UNEXPECTED_STAGE_MARKER_NAME)
            .exists(),
        "the must-skip stage must never execute once the shutdown flag is observed \
         (skip-cascade regression); stderr: {stderr_captured}"
    );
    assert!(
        !marker_dir.path().join(PASSED_MARKER_NAME).exists(),
        "a signal-interrupted run must never report success via a PASSED marker"
    );
}

#[test]
fn sigterm_during_stage_execution_skips_remaining_stages_but_runs_cleanup() {
    run_signal_cleanup_case("-TERM");
}

#[test]
fn sigint_during_stage_execution_skips_remaining_stages_but_runs_cleanup() {
    run_signal_cleanup_case("-INT");
}
