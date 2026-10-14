//! C ABI v1 for the native shells.
//!
//! Every exported function takes and returns integers only, and reports a typed
//! `MobileStatus` code (`rn_mobile_abi_version` returns a plain integer, see below).
//! The numeric values are stable.
//!
//! Descriptor ownership for `rn_mobile_start_raw_fd`:
//! - `fd < 0`: refused as `InvalidArgument`. Nothing is owned and nothing is closed.
//! - `0 <= fd <= 2` (stdio): refused as `StdioNotAdopted`. Nothing is adopted and nothing
//!   is closed. The caller still owns the integer and must close it if it is its own.
//! - `fd >= 3`: ownership transfers to this call on every outcome. The descriptor is
//!   closed exactly once when the call returns, including after a caught panic. The
//!   caller must not close it. While the engine is unwired (MC1c-2) the outcome is
//!   `Unsupported`.
//!
//! Requirement for MC1c-2 (not implemented here): a second adoption of the same integer
//! must be refused by started-state, because the second call would close a descriptor
//! number that may have been reused.
//!
//! The native shell never closes a descriptor it has passed here. The JNI shim follows
//! that rule (see `jni_shim`).

use std::os::fd::{FromRawFd, OwnedFd};

use crate::panic::{guard, guard_u32, injection_point};

/// ABI version of this surface. Bump on any change to an exported signature or code.
pub const RN_MOBILE_ABI_VERSION: u32 = 1;

/// Lowest descriptor number this crate will adopt. Stdio is never adopted.
const FIRST_ADOPTABLE_FD: i32 = 3;

/// Typed status codes returned by every status-returning export. The numeric values are
/// stable and pairwise distinct.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileStatus {
    /// The operation succeeded.
    Ok = 0,
    /// A negative descriptor was passed. Nothing was owned and nothing was closed.
    InvalidArgument = 1,
    /// The operation is not available in this build. The engine arrives in MC1c-2.
    Unsupported = 2,
    /// A panic was caught at the boundary. It never crossed the C ABI.
    PanicCaught = 3,
    /// A stdio descriptor (0..=2) was passed. Nothing was adopted and nothing was closed.
    /// The caller still owns the integer.
    StdioNotAdopted = 4,
}

impl MobileStatus {
    /// The stable C integer for this status.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

// SAFETY: `no_mangle` only fixes the exported symbol name. Two duties remain with the
// build and the Kotlin side: the name must be unique across the whole linked image, so no
// other library in the process may export `rn_mobile_*`; and the native declaration must
// match this Rust signature.
/// Returns the ABI version. A panic is caught and returns 0, which the native side must
/// treat as a version mismatch.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn rn_mobile_abi_version() -> u32 {
    guard_u32(|| {
        injection_point("abi");
        RN_MOBILE_ABI_VERSION
    })
}

// SAFETY: same duties as `rn_mobile_abi_version` (unique symbol, matching declaration).
/// Adopts a raw descriptor and starts the mobile core. Returns a `MobileStatus` code.
///
/// The ownership rules are documented at the top of this module.
///
/// # Safety
///
/// For `fd >= 3`, the caller transfers ownership of `fd` to this call. It must be an open
/// descriptor that no other owner (Rust, native code, or another library) will close or
/// use afterwards. On Android, pass `pfd.dup().detachFd()`, keeping the original
/// `ParcelFileDescriptor` in native code (design section 3.10).
///
/// What the caller must do after each status:
/// - `Unsupported`, `PanicCaught`: Rust has closed the descriptor. The caller must not
///   close or use it. (This export never returns `Ok`: the engine is unwired until MC1c-2.)
/// - `InvalidArgument` (negative `fd`) and `StdioNotAdopted` (`fd` 0..=2): nothing was
///   transferred. The caller still owns the integer and must close it if it is its own.
///
/// Passing a descriptor still owned elsewhere can close a descriptor that is in use.
/// Double adoption of one fd stays possible until MC1c-2 (started-state refusal is an
/// MC1c-2 requirement, not implemented in this build). Kotlin must never call start twice.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
// SAFETY: this export has the `# Safety` contract above. The body only forwards `fd`
// to `start_raw_fd` under the same contract, inside the panic boundary.
pub unsafe extern "C" fn rn_mobile_start_raw_fd(fd: i32) -> i32 {
    guard(|| {
        // SAFETY: the caller of this export upholds its `# Safety` contract, which
        // transfers ownership of `fd` to this call.
        unsafe { start_raw_fd(fd) }
    })
    .code()
}

// SAFETY: same duties as `rn_mobile_abi_version` (unique symbol, matching declaration).
/// Stops the mobile core. Returns a `MobileStatus` code.
///
/// No core can be running before `rn_mobile_start_raw_fd` succeeds, so this is
/// `Unsupported` in this build, which matches the start path.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn rn_mobile_stop() -> i32 {
    guard(stop).code()
}

/// Adopts `fd` if it is a descriptor this crate may own, then reports the outcome.
///
/// # Safety
///
/// Same contract as `rn_mobile_start_raw_fd`: the caller transfers ownership of `fd`.
/// Refused values (negative or stdio) transfer nothing, so the contract matters only
/// for `fd >= 3`.
#[allow(unsafe_code)]
// SAFETY: the caller upholds the `# Safety` contract above. Refused values take no
// ownership; accepted values are adopted exactly once, by `adopt_checked`.
unsafe fn start_raw_fd(fd: i32) -> MobileStatus {
    // SAFETY: forwarded from this function's `# Safety` contract.
    let adopted = match unsafe { adopt_checked(fd) } {
        Ok(adopted) => adopted,
        Err(status) => return status,
    };
    // The adopted descriptor is owned by this binding and closed on every path out of
    // this function, including a panic raised below and caught by the guard.
    let _adopted = adopted;
    injection_point("start");
    // The engine is unwired (MC1c-2), so every path releases the descriptor by drop.
    MobileStatus::Unsupported
}

fn stop() -> MobileStatus {
    injection_point("stop");
    MobileStatus::Unsupported
}

/// Refuses values this crate may not own, then adopts the rest.
///
/// # Safety
///
/// Same contract as `rn_mobile_start_raw_fd`. A refused value takes no ownership.
#[allow(unsafe_code)]
// SAFETY: the caller upholds the `# Safety` contract above. Only `fd >= 3` reaches the
// adoption call, and ownership of that descriptor is the caller's to transfer.
unsafe fn adopt_checked(fd: i32) -> Result<OwnedFd, MobileStatus> {
    if fd < 0 {
        return Err(MobileStatus::InvalidArgument);
    }
    if fd < FIRST_ADOPTABLE_FD {
        return Err(MobileStatus::StdioNotAdopted);
    }
    // SAFETY: `fd >= 3` here, and the caller's contract transfers ownership of it.
    Ok(unsafe { adopt_raw_fd(fd) })
}

/// The only place in the crate where a C integer becomes an owned descriptor: the single
/// raw-descriptor adoption call.
///
/// Naming note: design sections 3.10 and 5.1 call this step `adopt_tun_fd`. The crate
/// keeps the name `adopt_raw_fd`, because the adopted descriptor is not tun-specific.
///
/// # Safety
///
/// `fd` must be an open descriptor whose sole ownership the caller transfers to the
/// returned `OwnedFd`.
#[allow(unsafe_code)]
// SAFETY: the caller upholds the `# Safety` contract above; the returned OwnedFd is the
// only owner and closes the descriptor exactly once, on drop.
unsafe fn adopt_raw_fd(fd: i32) -> OwnedFd {
    // SAFETY: ownership of `fd` is transferred to this function by its caller, so no
    // other owner exists to double-close it.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::{IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::{
        MobileStatus, RN_MOBILE_ABI_VERSION, rn_mobile_abi_version, rn_mobile_start_raw_fd,
        rn_mobile_stop,
    };
    use crate::panic::{arm_injection, disarm_injection};

    /// Returns the peer end and the raw integer of the other end, which the caller now owns.
    fn pair_with_raw_end() -> std::io::Result<(UnixStream, i32)> {
        let (peer, end) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let raw = OwnedFd::from(end).into_raw_fd();
        Ok((peer, raw))
    }

    /// Calls the start export under the test's ownership transfer.
    fn start(fd: i32) -> i32 {
        // SAFETY: each caller passes either a descriptor it has just created and handed
        // over exactly once, or a value that the export refuses before adoption.
        unsafe { rn_mobile_start_raw_fd(fd) }
    }

    #[test]
    fn statuses_are_stable_and_pairwise_distinct() {
        let codes = [
            MobileStatus::Ok.code(),
            MobileStatus::InvalidArgument.code(),
            MobileStatus::Unsupported.code(),
            MobileStatus::PanicCaught.code(),
            MobileStatus::StdioNotAdopted.code(),
        ];
        assert_eq!(codes, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(RN_MOBILE_ABI_VERSION, 1);
        assert_eq!(rn_mobile_abi_version(), 1);
    }

    #[test]
    fn valid_fd_is_adopted_returns_unsupported_and_is_closed() -> std::io::Result<()> {
        let (mut peer, raw) = pair_with_raw_end()?;
        assert_eq!(start(raw), MobileStatus::Unsupported.code());
        let mut buf = [0u8; 1];
        // Ok(0) means the peer saw EOF, so the adopted descriptor was closed.
        assert_eq!(peer.read(&mut buf)?, 0);
        Ok(())
    }

    #[test]
    fn negative_fd_is_invalid_and_closes_nothing() -> std::io::Result<()> {
        let (mut peer, mut local) = UnixStream::pair()?;
        local.set_read_timeout(Some(Duration::from_secs(5)))?;
        assert_eq!(start(-1), MobileStatus::InvalidArgument.code());
        assert_eq!(start(i32::MIN), MobileStatus::InvalidArgument.code());
        // The unrelated pair is still open in both directions.
        peer.write_all(b"x")?;
        let mut buf = [0u8; 1];
        assert_eq!(local.read(&mut buf)?, 1);
        assert_eq!(buf[0], b'x');
        Ok(())
    }

    #[test]
    fn stdio_range_is_refused_with_its_own_code_and_adopts_nothing() {
        for fd in 0..=2 {
            assert_eq!(start(fd), MobileStatus::StdioNotAdopted.code());
        }
    }

    #[test]
    fn stop_is_unsupported_until_engine_is_wired() {
        assert_eq!(rn_mobile_stop(), MobileStatus::Unsupported.code());
    }

    #[test]
    fn injected_panic_in_abi_version_returns_zero() {
        arm_injection("abi");
        let version = rn_mobile_abi_version();
        disarm_injection();
        assert_eq!(version, 0);
    }

    #[test]
    fn injected_panic_in_start_returns_panic_caught_and_closes_the_fd() -> std::io::Result<()> {
        let (mut peer, raw) = pair_with_raw_end()?;
        arm_injection("start");
        let status = start(raw);
        disarm_injection();
        assert_eq!(status, MobileStatus::PanicCaught.code());
        let mut buf = [0u8; 1];
        // The unwind dropped the adopted descriptor, so the peer sees EOF.
        assert_eq!(peer.read(&mut buf)?, 0);
        Ok(())
    }

    #[test]
    fn injected_panic_in_stop_returns_panic_caught() {
        arm_injection("stop");
        let status = rn_mobile_stop();
        disarm_injection();
        assert_eq!(status, MobileStatus::PanicCaught.code());
    }
}
