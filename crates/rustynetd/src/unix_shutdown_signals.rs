//! Unix graceful-shutdown signal scaffolding.
//!
//! `rustynetd` runs as a long-lived systemd unit on Linux and as a
//! launchd job on macOS. When the service manager asks the daemon to
//! stop — `systemctl stop`, `systemctl restart`, `launchctl unload`,
//! or an operator-driven SIGTERM — we must run the dataplane
//! teardown (rollback the killswitch nftables programming, remove
//! the WireGuard interface) before the process exits. If we exit
//! ungracefully the next start hits L8's boot-time leak-window gate
//! (`linux_killswitch_boot_check`) because the kernel-side state is
//! mid-shape: tunnel interface still up, killswitch table gone.
//!
//! Historically only the Windows SCM stop path called
//! `Phase10Controller::shutdown`. The Unix daemon loop had no signal
//! integration at all, so `systemctl restart` SIGKILLed the daemon
//! after the default 90 s stop-timeout and left the kernel state
//! split. This module is the missing Unix half: install a SIGTERM
//! and SIGINT flag-handler via `signal_hook::flag::register`, and
//! expose a `requested()` query the daemon loop polls every
//! iteration alongside the Windows `windows_service_stop_requested`
//! check.
//!
//! The handler itself only touches an `AtomicBool`. That keeps the
//! signal-handler body async-signal-safe: no allocation, no logging,
//! no locks. The actual graceful shutdown work runs back on the main
//! thread after the loop observes the flag.

#![cfg(unix)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Handle returned by [`install_unix_shutdown_signals`]. The daemon
/// loop polls [`Self::requested`] every iteration and breaks out of
/// the main loop when it returns `true`, so the post-loop graceful
/// shutdown sequence (controller rollback + key scrubbing) can run.
#[derive(Clone)]
pub struct UnixShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl UnixShutdownHandle {
    /// Returns `true` once SIGTERM or SIGINT has been delivered.
    /// Cheap to call on every loop iteration — a single relaxed
    /// atomic load behind a memory acquire ordering.
    pub fn requested(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Test-only: synthesize a shutdown request without sending a
    /// real signal. Lets unit tests cover the loop-observes-flag
    /// branch without racing the OS signal delivery.
    #[cfg(test)]
    pub fn force_request_for_test(&self) {
        self.flag.store(true, Ordering::Release);
    }
}

/// Install SIGTERM and SIGINT flag-handlers and return the polling
/// handle. Failure to install must be reported up to the caller as a
/// startup error: a daemon without shutdown signal coverage would
/// re-introduce the L8 leak-window every time the service is
/// restarted, so silently degrading is not acceptable.
///
/// Calling this more than once in the same process is allowed —
/// `signal_hook::flag::register` is additive, so a second install
/// would simply set the same flag from the same handler. The daemon
/// only calls it once during `run_daemon` bootstrap.
pub fn install_unix_shutdown_signals() -> Result<UnixShutdownHandle, std::io::Error> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(UnixShutdownHandle { flag })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // `signal_hook::flag::register` is additive and process-global, and
    // `sigterm_delivered_to_self_flips_flag` raises a real SIGTERM at this
    // process. Under `cargo test`'s default multi-thread harness those two
    // tests race: the raised SIGTERM flips every registered flag — including the
    // one `install_returns_handle_without_signalling_existing_process_state`
    // asserts stays false — which intermittently reds the workspace test gate.
    // Serialize the two process-global signal tests through a shared mutex so
    // they never overlap. Recover from a poisoned lock (a prior panicking test)
    // so serialization still holds for the rest.
    static SIGNAL_TEST_GUARD: Mutex<()> = Mutex::new(());

    fn lock_signal_tests() -> MutexGuard<'static, ()> {
        SIGNAL_TEST_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn handle_starts_unrequested() {
        let handle = UnixShutdownHandle {
            flag: Arc::new(AtomicBool::new(false)),
        };
        assert!(
            !handle.requested(),
            "fresh handle must not report a pending shutdown"
        );
    }

    #[test]
    fn force_request_makes_requested_true() {
        let handle = UnixShutdownHandle {
            flag: Arc::new(AtomicBool::new(false)),
        };
        handle.force_request_for_test();
        assert!(handle.requested());
    }

    #[test]
    fn install_returns_handle_without_signalling_existing_process_state() {
        // Serialize against sigterm_delivered_to_self_flips_flag: its raised
        // SIGTERM is process-global and would otherwise flip this test's
        // registered flag mid-assertion.
        let _guard = lock_signal_tests();
        // Installing the handlers must not retroactively set the
        // flag — only an actual SIGTERM/SIGINT delivered after
        // install should flip it. Verifies the initial flag value
        // contract.
        let handle = install_unix_shutdown_signals().expect("install signal handlers");
        assert!(
            !handle.requested(),
            "no SIGTERM/SIGINT has been delivered; flag must remain false"
        );
    }

    #[test]
    fn sigterm_delivered_to_self_flips_flag() {
        // Serialize against
        // install_returns_handle_without_signalling_existing_process_state: the
        // SIGTERM raised below is process-global and would otherwise flip that
        // test's flag while it asserts the flag stays false.
        let _guard = lock_signal_tests();
        // Real end-to-end coverage: install the handlers, raise
        // SIGTERM against our own process, then confirm the flag
        // observes the signal. `nix::sys::signal::raise` is the
        // standard way to synthesize the signal without spawning a
        // helper, and `signal_hook` guarantees the registered atomic
        // is set from inside the handler.
        use std::time::{Duration, Instant};

        let handle = install_unix_shutdown_signals().expect("install signal handlers");
        // SAFETY of the underlying signal-hook handler: it only
        // performs an atomic store, which is signal-safe on every
        // supported architecture.
        let pid = std::process::id();
        // libc::kill is the most portable way to raise a specific
        // signal at our own process from safe Rust through `nix`.
        // The `signal` nix feature is not enabled in this crate, so
        // we go through `signal_hook::low_level::raise` instead,
        // which wraps `libc::raise` and is part of the high-level
        // signal-hook surface we already depend on.
        signal_hook::low_level::raise(signal_hook::consts::SIGTERM).expect("raise SIGTERM at self");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !handle.requested() {
            if Instant::now() >= deadline {
                panic!(
                    "SIGTERM delivered to pid {pid} but shutdown handle did not observe it within 2 s"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handle.requested());
    }
}
