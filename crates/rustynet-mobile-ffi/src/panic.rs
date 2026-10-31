//! Panic containment for every exported function.
//!
//! Rust must never unwind into native code. Each export runs its body through a guard,
//! which turns a caught panic into a typed status (`guard`) or into the value 0
//! (`guard_u32`, for `rn_mobile_abi_version`). Locals in the body, including any
//! `OwnedFd`, are dropped during the unwind.
//!
//! The panic payload is never printed, and it is never dropped inside the guard. A
//! payload whose `Drop` panics would otherwise escape the guard. The fixed-text hook
//! below replaces the default hook for this process. The default hook would print the
//! payload, which can carry data that must not be logged.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use crate::c_abi::MobileStatus;

const FIXED_PANIC_TEXT: &[u8] =
    b"rustynet-mobile-ffi: panic caught at the C ABI boundary; details suppressed\n";

static HOOK: Once = Once::new();

thread_local! {
    /// True while this thread runs a guarded body. Only those panics get the fixed text.
    #[allow(clippy::missing_const_for_thread_local)]
    static IN_GUARD: Cell<bool> = Cell::new(false);
}

/// Installs, once per process, a hook that chains to the previous hook. Panics raised
/// inside a guard print only the fixed text. Every other panic (for example a test
/// failure, or a panic in code outside this crate) goes to the previous hook unchanged.
fn install_fixed_panic_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if IN_GUARD.with(Cell::get) {
                // Fixed text only. The write result is ignored, because a hook must not panic.
                let _ = std::io::Write::write_all(&mut std::io::stderr(), FIXED_PANIC_TEXT);
            } else {
                previous(info);
            }
        }));
    });
}

/// Runs `body` with the guard flag set. Returns its result, or the panic payload if it panicked.
fn run_guarded<R>(body: impl FnOnce() -> R) -> Result<R, Box<dyn std::any::Any + Send>> {
    install_fixed_panic_hook();
    // Save and restore the previous value, so a guard nested inside another guard does not
    // clear the outer guard's flag.
    let previous = IN_GUARD.with(|flag| flag.replace(true));
    let outcome = catch_unwind(AssertUnwindSafe(body));
    IN_GUARD.with(|flag| flag.set(previous));
    outcome
}

/// Runs `body` and converts an unwinding panic into a typed status.
pub(crate) fn guard<F>(body: F) -> MobileStatus
where
    F: FnOnce() -> MobileStatus,
{
    match run_guarded(body) {
        Ok(status) => status,
        Err(payload) => {
            std::mem::forget(payload);
            MobileStatus::PanicCaught
        }
    }
}

/// Runs `body` and converts an unwinding panic into 0.
pub(crate) fn guard_u32<F>(body: F) -> u32
where
    F: FnOnce() -> u32,
{
    match run_guarded(body) {
        Ok(value) => value,
        Err(payload) => {
            std::mem::forget(payload);
            0
        }
    }
}

/// Test-only injection points. Production builds compile them to nothing, so no test seam
/// exists in a shipped library.
#[cfg(test)]
#[allow(clippy::missing_const_for_thread_local)]
mod injection {
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<Option<&'static str>> = const { Cell::new(None) };
    }

    pub(crate) fn arm(site: &'static str) {
        ARMED.with(|armed| armed.set(Some(site)));
    }

    pub(crate) fn disarm() {
        ARMED.with(|armed| armed.set(None));
    }

    pub(crate) fn point(site: &'static str) {
        if ARMED.with(|armed| armed.get()) == Some(site) {
            panic!("injected panic at {site}");
        }
    }
}

#[cfg(test)]
pub(crate) use injection::{
    arm as arm_injection, disarm as disarm_injection, point as injection_point,
};

/// Production no-op. The injection points exist only in test builds.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn injection_point(_site: &'static str) {}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::{guard, guard_u32};
    use crate::c_abi::MobileStatus;

    /// A payload whose `Drop` panics. The guard must not drop it, so no panic can escape.
    struct PanickingDrop;

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            panic!("payload drop must never run inside the guard");
        }
    }

    #[test]
    fn panic_inside_wrapped_call_becomes_error_code() {
        let status = guard(|| panic!("provoked panic inside a wrapped call"));
        assert_eq!(status, MobileStatus::PanicCaught);
        assert_eq!(status.code(), 3);
    }

    #[test]
    fn guard_u32_converts_panic_to_zero() {
        assert_eq!(guard_u32(|| panic!("provoked panic")), 0);
        assert_eq!(guard_u32(|| 7), 7);
    }

    #[test]
    fn guard_is_usable_again_after_a_caught_panic() {
        let _ = guard(|| panic!("provoked panic"));
        assert_eq!(
            guard(|| MobileStatus::Unsupported),
            MobileStatus::Unsupported
        );
    }

    #[test]
    fn panic_payload_with_panicking_drop_does_not_escape_the_guard() {
        let status = guard(|| std::panic::panic_any(PanickingDrop));
        assert_eq!(status, MobileStatus::PanicCaught);
    }

    #[test]
    fn unwinding_drops_an_adopted_fd_exactly_once() -> std::io::Result<()> {
        let (mut peer, end) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let status = guard(move || {
            let _adopted = OwnedFd::from(end);
            panic!("provoked panic after adoption");
        });
        assert_eq!(status, MobileStatus::PanicCaught);
        let mut buf = [0u8; 1];
        // Ok(0) means the peer saw EOF, so the adopted end was closed by the unwind.
        assert_eq!(peer.read(&mut buf)?, 0);
        Ok(())
    }
}
