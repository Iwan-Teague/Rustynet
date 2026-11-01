//! JNI shim skeleton for the Android shell (MC1d, compile scope).
//!
//! The shim has no logic. Each entry point converts JNI types to C ABI integers and
//! forwards to `c_abi`. The `jni` crate is not used. It would be a new third-party
//! dependency, and the shim needs only a handful of raw types, which are defined here.
//!
//! Ownership. The Android shell passes `pfd.dup().detachFd()` to `startRawFd`. The
//! native shell keeps the original `ParcelFileDescriptor` (design section 3.10). The
//! shim hands the integer to `c_abi::rn_mobile_start_raw_fd` unchanged. The C ABI takes
//! ownership of every descriptor it adopts, and closes it on every path after adoption.
//! The shim therefore never closes a descriptor itself, on success or on error. A second
//! close here could hit a descriptor number that has been reused.
//!
//! Safety. `startRawFd` is an `unsafe extern "system"` function. Calling it from Rust
//! requires the same contract as `rn_mobile_start_raw_fd`. The JVM is the only expected
//! caller, and the Kotlin side must follow that contract.
//!
//! PLACEHOLDER: the Kotlin class `com.rustynet.mobile.NativeBridge` is a stand-in until
//! the Android application package is decided. The Kotlin declaration must match each
//! Rust signature exactly: `external fun startRawFd(fd: Int): Int`, with a static or
//! instance choice that matches the first class argument. A `companion object` without
//! `@JvmStatic` changes the symbol to `..._00024Companion_...`. Renaming the class means
//! renaming the exported symbols in this file and in the Kotlin side together.

use std::ffi::c_void;

use crate::c_abi;

/// JNI `jint`.
#[allow(non_camel_case_types)]
pub type jint = i32;
/// JNI `jlong`. Reserved for handle values in later slices.
#[allow(non_camel_case_types)]
pub type jlong = i64;
/// Opaque JNI environment or class reference. The shim never dereferences it.
#[allow(non_camel_case_types)]
pub type jref = *mut c_void;

// SAFETY: `no_mangle` only fixes the exported symbol name. The symbol must be unique across
// the linked image, and the Kotlin `external fun` declaration must match this signature.
// PLACEHOLDER: final package decided in MC-A1
/// JNI entry point: returns the C ABI version (0 if the core panicked).
#[unsafe(no_mangle)]
#[allow(unsafe_code, non_snake_case)]
pub extern "system" fn Java_com_rustynet_mobile_NativeBridge_abiVersion(
    _env: jref,
    _class: jref,
) -> jint {
    c_abi::rn_mobile_abi_version() as jint
}

// SAFETY: same duties as `abiVersion` (unique symbol, matching declaration).
// PLACEHOLDER: final package decided in MC-A1
/// JNI entry point: adopts a detached descriptor and starts the core. Returns a status code.
///
/// The descriptor is handed to the C ABI and is not closed here. See the module docs.
///
/// # Safety
///
/// `fd` must be the integer of `pfd.dup().detachFd()`, which transfers ownership of an
/// open descriptor to native code. The caller must not close it or use it after the call.
#[unsafe(no_mangle)]
#[allow(unsafe_code, non_snake_case)]
// SAFETY: this export has the `# Safety` contract above. The body forwards `fd` once and
// keeps no copy, so the C ABI becomes its only owner.
pub unsafe extern "system" fn Java_com_rustynet_mobile_NativeBridge_startRawFd(
    _env: jref,
    _class: jref,
    fd: jint,
) -> jint {
    // SAFETY: the Kotlin caller passes the `pfd.dup().detachFd()` integer, which is the
    // `# Safety` contract of `rn_mobile_start_raw_fd`. This call forwards it once.
    unsafe { c_abi::rn_mobile_start_raw_fd(fd) }
}

// SAFETY: same duties as `abiVersion` (unique symbol, matching declaration).
// PLACEHOLDER: final package decided in MC-A1
/// JNI entry point: stops the core. Returns a status code.
#[unsafe(no_mangle)]
#[allow(unsafe_code, non_snake_case)]
pub extern "system" fn Java_com_rustynet_mobile_NativeBridge_stop(
    _env: jref,
    _class: jref,
) -> jint {
    c_abi::rn_mobile_stop()
}

#[cfg(test)]
#[allow(non_snake_case, unsafe_code)]
mod tests {
    use std::io::Read;
    use std::os::fd::{IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::{
        Java_com_rustynet_mobile_NativeBridge_abiVersion,
        Java_com_rustynet_mobile_NativeBridge_startRawFd,
        Java_com_rustynet_mobile_NativeBridge_stop,
    };
    use crate::c_abi::MobileStatus;
    use crate::panic::{arm_injection, disarm_injection};

    /// Calls the JNI start entry under the test's ownership transfer.
    fn jni_start(fd: i32) -> i32 {
        // SAFETY: each caller passes either a descriptor it has just created and handed
        // over exactly once, or a value that the export refuses before adoption.
        unsafe {
            Java_com_rustynet_mobile_NativeBridge_startRawFd(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fd,
            )
        }
    }

    #[test]
    fn jni_abi_version_forwards_to_c_abi() {
        assert_eq!(
            Java_com_rustynet_mobile_NativeBridge_abiVersion(
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            1
        );
    }

    #[test]
    fn jni_negative_fd_is_invalid() {
        assert_eq!(jni_start(-1), MobileStatus::InvalidArgument.code());
    }

    #[test]
    fn jni_stdio_fd_is_refused_with_its_own_code() {
        assert_eq!(jni_start(0), MobileStatus::StdioNotAdopted.code());
    }

    #[test]
    fn jni_start_hands_fd_to_c_abi_which_closes_it_once() -> std::io::Result<()> {
        let (mut peer, end) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let raw = OwnedFd::from(end).into_raw_fd();
        assert_eq!(jni_start(raw), MobileStatus::Unsupported.code());
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf)?, 0);
        Ok(())
    }

    #[test]
    fn jni_stop_is_unsupported_until_engine_is_wired() {
        assert_eq!(
            Java_com_rustynet_mobile_NativeBridge_stop(std::ptr::null_mut(), std::ptr::null_mut()),
            MobileStatus::Unsupported.code()
        );
    }

    #[test]
    fn jni_injected_panic_in_abi_version_returns_zero() {
        arm_injection("abi");
        let version = Java_com_rustynet_mobile_NativeBridge_abiVersion(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        disarm_injection();
        assert_eq!(version, 0);
    }

    #[test]
    fn jni_injected_panic_in_start_returns_panic_caught_and_closes_the_fd() -> std::io::Result<()> {
        let (mut peer, end) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let raw = OwnedFd::from(end).into_raw_fd();
        arm_injection("start");
        let status = jni_start(raw);
        disarm_injection();
        assert_eq!(status, MobileStatus::PanicCaught.code());
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf)?, 0);
        Ok(())
    }

    #[test]
    fn jni_injected_panic_in_stop_returns_panic_caught() {
        arm_injection("stop");
        let status =
            Java_com_rustynet_mobile_NativeBridge_stop(std::ptr::null_mut(), std::ptr::null_mut());
        disarm_injection();
        assert_eq!(status, MobileStatus::PanicCaught.code());
    }
}
